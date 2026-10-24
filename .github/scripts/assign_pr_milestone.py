#!/usr/bin/env python3
"""Assign a PR milestone from explicit same-repository issue references.

Only run trusted default-branch code in pull_request_target. Never checkout the
contributor's branch, execute PR content, or interpolate PR text into a shell.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener


class MilestonePolicyError(Exception):
    """An ambiguous or unverifiable milestone must not be assigned."""


PRIMARY = re.compile(r"(?im)^[ \t]*Primary issue:[ \t]*#([1-9][0-9]*)[ \t]*$")
CLOSING = re.compile(
    r"(?im)^[ \t]*(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)[ \t]+#([1-9][0-9]*)\b"
)
TITLE_TRAILER = re.compile(r"\([ \t]*(?:#[1-9][0-9]*[ \t,;]*)+\)[ \t]*$")
ISSUE_REF = re.compile(r"#([1-9][0-9]*)\b")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")


def references(title: str, body: str) -> tuple[int | None, tuple[int, ...]]:
    explicit = {int(n) for n in PRIMARY.findall(body)}
    if len(explicit) > 1:
        raise MilestonePolicyError("Conflicting 'Primary issue:' references")
    primary = next(iter(explicit), None)
    candidate_numbers = [int(n) for n in CLOSING.findall(body)]
    trailing = TITLE_TRAILER.search(title)
    if trailing:
        candidate_numbers.extend(int(n) for n in ISSUE_REF.findall(trailing.group(0)))
    return primary, tuple(dict.fromkeys(candidate_numbers))


def choose_milestone(
    primary: int | None,
    candidates: tuple[int, ...],
    fetch_issue,
) -> int:
    numbers = tuple(dict.fromkeys(((primary,) if primary is not None else ()) + candidates))
    if not numbers:
        raise MilestonePolicyError(
            "Missing primary issue: add 'Primary issue: #N' to the PR body, "
            "or assign its milestone manually"
        )

    milestones: dict[int, int] = {}
    for number in numbers:
        issue = fetch_issue(number)
        if issue.get("pull_request") is not None:
            raise MilestonePolicyError(f"#{number} is a PR, not an issue")
        ms = issue.get("milestone")
        if not isinstance(ms, dict) or type(ms.get("number")) is not int or ms["number"] <= 0:
            raise MilestonePolicyError(f"Issue #{number} has no valid milestone")
        milestones[number] = ms["number"]

    if primary is not None:
        # The author explicitly identifies the primary deliverable. Other
        # closing/title references are checked and reported, never ignored.
        conflicts = [n for n, ms in milestones.items() if ms != milestones[primary]]
        if conflicts:
            raise MilestonePolicyError(
                "Milestone conflict: primary issue #"
                f"{primary} differs from referenced issues "
                + ", ".join(f"#{n}" for n in conflicts)
                + "; assign milestone manually after review"
            )
        return milestones[primary]

    distinct = set(milestones.values())
    if len(distinct) != 1:
        raise MilestonePolicyError(
            "Milestone conflict across referenced issues: "
            + ", ".join(f"#{n}=milestone-{m}" for n, m in milestones.items())
            + "; assign milestone manually after review"
        )
    return next(iter(distinct))


class RejectRedirects(HTTPRedirectHandler):
    """Never forward a GitHub Actions token to a redirected origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def api_request(url: str, token: str, method: str = "GET", payload: dict | None = None) -> dict:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = Request(
        url,
        data=data,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "repocache-milestone-governance",
            **({"Content-Type": "application/json"} if data is not None else {}),
        },
    )
    try:
        with build_opener(RejectRedirects).open(req, timeout=15) as response:
            result = json.load(response)
    except HTTPError as exc:
        raise MilestonePolicyError(f"GitHub API returned HTTP {exc.code} on {method}") from None
    except (URLError, TimeoutError, ValueError) as exc:
        raise MilestonePolicyError(f"GitHub API request failed ({type(exc).__name__})") from None
    if not isinstance(result, dict):
        raise MilestonePolicyError("Unexpected GitHub API response")
    return result


def reconcile(repo: str, pr_number: int, token: str, requester=api_request) -> str:
    if not REPOSITORY.fullmatch(repo) or pr_number <= 0:
        raise MilestonePolicyError("Invalid repository or PR number")
    root = f"https://api.github.com/repos/{repo}/issues"

    def get_issue(number: int) -> dict:
        result = requester(f"{root}/{number}", token)
        if result.get("number") != number:
            raise MilestonePolicyError(f"Unexpected issue response for #{number}")
        return result

    pr = get_issue(pr_number)
    if not isinstance(pr.get("pull_request"), dict):
        raise MilestonePolicyError("Target is not a pull request")
    if pr.get("state") != "open":
        return "Skipped closed PR"
    current = pr.get("milestone")
    if current is not None:
        if (not isinstance(current, dict) or type(current.get("number")) is not int
                or current["number"] <= 0):
            raise MilestonePolicyError("Invalid existing PR milestone metadata")
        return f"Preserved manually assigned milestone #{current['number']}"

    primary, linked = references(pr.get("title") or "", pr.get("body") or "")
    milestone = choose_milestone(primary, linked, get_issue)
    patched = requester(f"{root}/{pr_number}", token, "PATCH", {"milestone": milestone})
    confirmed = patched.get("milestone")
    if (not isinstance(confirmed, dict) or type(confirmed.get("number")) is not int
            or confirmed["number"] != milestone):
        raise MilestonePolicyError("GitHub API did not confirm milestone assignment")
    return f"Assigned milestone #{milestone} to PR #{pr_number}"


def main() -> int:
    try:
        repo = os.environ["GITHUB_REPOSITORY"]
        token = os.environ["GH_TOKEN"]
        event_path = Path(os.environ["GITHUB_EVENT_PATH"])
        event = json.loads(event_path.read_text(encoding="utf-8"))
        pr = event.get("pull_request")
        if not isinstance(pr, dict) or type(pr.get("number")) is not int:
            raise MilestonePolicyError("Expected a pull_request_target event")
        if pr["number"] != event.get("number"):
            raise MilestonePolicyError("Inconsistent GitHub event PR number")
        print(reconcile(repo, pr["number"], token))
        return 0
    except (MilestonePolicyError, KeyError, ValueError, OSError) as exc:
        print(f"Milestone gate: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
