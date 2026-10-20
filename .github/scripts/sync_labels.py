#!/usr/bin/env python3
"""Validate or synchronize REPOCACHE GitHub issue label colors.

Uses GitHub's built-in GITHUB_TOKEN. No personal access token is required.
Never removes labels, changes issue assignments, or modifies source files.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LABELS = ROOT / "labels.json"
NAME_PATTERN = re.compile(r"^(?:type|area|priority):[A-Za-z0-9-]+$")
COLOR_PATTERN = re.compile(r"^[0-9A-Fa-f]{6}$")


def validate():
    entries = json.loads(LABELS.read_text(encoding="utf-8"))
    if not isinstance(entries, list) or not entries:
        raise ValueError("The label palette must be a non-empty JSON array")
    names = set()
    for label in entries:
        if not isinstance(label, dict) or set(label) != {"name", "color", "description"}:
            raise ValueError("Each label requires name, color, and description")
        name, color, description = (label[k] for k in ("name", "color", "description"))
        if not isinstance(name, str) or not NAME_PATTERN.fullmatch(name) or name in names:
            raise ValueError(f"Invalid or duplicate label name: {name!r}")
        if not isinstance(color, str) or not COLOR_PATTERN.fullmatch(color):
            raise ValueError(f"Invalid six-character HEX color for {name}")
        if not isinstance(description, str) or not description or len(description) > 100:
            raise ValueError(f"Invalid label description for {name}")
        names.add(name)
    return entries


def request(method, url, token, payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "repocache-label-synchronizer",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise RuntimeError(f"GitHub label API failed (HTTP {exc.code})") from exc
        return 404


def apply(entries):
    token = os.environ.get("GH_TOKEN", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if not token or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise RuntimeError("GH_TOKEN and GITHUB_REPOSITORY are required")
    base = f"https://api.github.com/repos/{repo}/labels"
    for label in entries:
        name = label["name"]
        url = base + "/" + urllib.parse.quote(name, safe="")
        status = request("PATCH", url, token, {"color": label["color"], "description": label["description"]})
        if status == 404:
            created = request("POST", base, token, label)
            if created == 404:
                raise RuntimeError("Unable to create label: " + name)
            print(f"Created {name} (#{label['color']})")
        else:
            print(f"Updated {name} (#{label['color']})")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="Write label colors via the GitHub API")
    args = parser.parse_args()
    entries = validate()
    if args.apply:
        apply(entries)
    else:
        print(f"Valid label palette: {len(entries)} labels")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Label synchronization failed: {error}", file=sys.stderr)
        sys.exit(1)
