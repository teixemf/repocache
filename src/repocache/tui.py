"""Colorful Textual TUI with a read-only dashboard."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from urllib.parse import urlsplit
from datetime import datetime, timezone
from typing import Any, Dict, List

from rich.markup import escape
from rich.table import Table
from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import DataTable, Footer, Header, Sparkline, Static, TabbedContent, TabPane

from repocache.rendering import safe_markup
from repocache.submissions import SubmissionQueue, SubmissionError
from repocache.cli import human_bytes
from repocache.core import (
    Settings, _tail_bytes, disk_status, health, metrics, probe_upstream, service_status, snapshot, timestamp,
)


# This path is fixed in production: never honour untrusted environment overrides.
SUBMISSION_QUEUE_PATH = Path("/var/lib/repocache/submissions/queue.sqlite3")


class RepoCacheApp(App):
    TITLE = "◈ REPOCACHE Control Center"
    SUB_TITLE = "NGINX · Repository Proxy · Monitoring"
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("1", "tab('overview')", "Overview"),
        ("2", "tab('repos')", "Repositories"),
        ("3", "tab('metrics')", "Metrics"),
        ("4", "tab('diagnostics')", "Diagnostics"),
        ("5", "tab('submissions')", "Submissions"),
        ("y", "review_selected", "Review proposal"),
        ("n", "reject_selected", "Reject proposal"),
        ("u", "undo_review", "Undo review"),
        ("p", "period", "Period"),
        ("a", "toggle_auto", "Auto ON/OFF"),
        ("i", "refresh_interval", "Interval"),
        ("t", "probe_selected", "Probe selected repo"),
        ("f", "filter_selected_metrics", "Metrics for repo"),
        ("g", "global_metrics", "All metrics"),
    ]
    CSS = """
    Screen { background: #0a1220; color: #dce8f8; }
    Header { background: #102942; color: #e5f6ff; }
    Footer { background: #102942; color: #b9dbf5; }
    TabbedContent { height: 1fr; }
    Tabs { background: #101d30; color: #a0c5e8; }
    TabPane { padding: 0 1; }
    VerticalScroll { height: 1fr; }
    .kpis { height: 7; margin-bottom: 1; }
    .kpi { width: 1fr; min-width: 17; height: 7; border: round #285779; background: #111f34; padding: 0 1; margin-right: 1; }
    .duo { height: 11; margin-bottom: 1; }
    .half { width: 1fr; min-width: 23; border: round #285779; background: #101e30; padding: 0 1; margin-right: 1; }
    .panel { border: round #285779; background: #101e30; padding: 0 1; margin-bottom: 1; }
    #requests-title { height: 2; margin-top: 1; color: #72d7f4; text-style: bold; }
    #requests-graph { height: 5; margin-bottom: 1; min-width: 30; }
    #histogram { height: 8; min-width: 30; }
    #repo-table { height: 1fr; min-height: 8; background: #101e30; }
    #proposal-table { height: 1fr; min-height: 8; background: #101e30; }
    #repo-note { min-height: 3; height: auto; }
    #repo-detail { height: 10; }
    #metric-info { height: 10; }
    #metric-details { height: 8; }
    #health-table { height: 1fr; min-height: 8; }
    #activity { height: 10; }
    .note { color: #a4b7cd; margin-bottom: 1; }
    """

    def __init__(self, auto_refresh: bool = True, refresh_interval: int = 15) -> None:
        super().__init__()
        self.settings = Settings()
        self.periods = [1, 6, 24, 168, 720]
        self.period_labels = ["1h", "6h", "24h", "7d", "30d"]
        # DOMNode.auto_refresh belongs to Textual; do not assign to it.
        self.refresh_enabled = bool(auto_refresh)
        self.refresh_intervals = [5, 15, 30, 60]
        self.refresh_interval_index = (self.refresh_intervals.index(refresh_interval)
                                       if refresh_interval in self.refresh_intervals else 1)
        self._next_auto_at = 0.0
        self.period_index = 2
        self._busy = False
        self._cached: Dict[str, Any] = {}
        self._cached_at = 0.0
        self._all_repos: List[Dict[str, str]] = []
        self._latest: Dict[str, Any] = {}
        self._selected_repo: str = ""
        self._probe_results: Dict[str, Dict[str, str]] = {}
        self._repo_activity: Dict[str, str] = {}
        self._metrics_filter: str | None = None
        self._proposal_versions: Dict[str, int] = {}
        self._selected_proposal = ""
        self._review_confirmation: tuple[str, str] | None = None
        self._last_review: tuple[str, int] | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent(initial="overview"):
            with TabPane("◉ OVERVIEW", id="overview"):
                with VerticalScroll():
                    with Horizontal(classes="kpis"):
                        yield Static("NGINX: loading…", id="kpi-nginx", classes="kpi")
                        yield Static("HIT: loading…", id="kpi-hit", classes="kpi")
                        yield Static("REQUESTS: loading…", id="kpi-requests", classes="kpi")
                        yield Static("REPOS: loading…", id="kpi-repos", classes="kpi")
                    with Horizontal(classes="duo"):
                        yield Static("Storage", id="disk", classes="half")
                        yield Static("Cache overview", id="cache", classes="half")
                    yield Static("REQUESTS PER HOUR (collecting data…)", id="requests-title")
                    yield Sparkline(None, id="requests-graph", min_color="#175aa3", max_color="#38e2d3")
                    yield Static("Loading…", id="activity", classes="panel")
            with TabPane("▤ REPOSITORIES", id="repos"):
                yield Static("Discovering NGINX proxy routes…", id="repo-note", classes="note")
                yield DataTable(id="repo-table", cursor_type="row", zebra_stripes=True)
                yield Static("Select a repository to inspect. Press T to probe or F for its metrics.", id="repo-detail", classes="panel")
            with TabPane("▥ METRICS", id="metrics"):
                with VerticalScroll():
                    yield Static("Metrics observed in request logs (G: all repositories)", id="metric-info", classes="panel")
                    yield Static("REQUEST VOLUME PER HOUR", id="metric-title", classes="note")
                    yield Sparkline(None, id="histogram", min_color="#215ca7", max_color="#27e6c2")
                    yield Static("Time ranges and limitations", id="metric-details", classes="panel")
            with TabPane("✚ SUBMISSIONS", id="submissions"):
                yield Static("No network intake is activated by this screen.", classes="note")
                yield Static("Root-only review of pending metadata", id="proposal-note", classes="panel")
                yield DataTable(id="proposal-table", cursor_type="row", zebra_stripes=True)
                yield Static("Select a proposal, then press Y/Y to review or N/N to reject. U undoes the last decision. Review never publishes routes.", id="proposal-detail", classes="panel")
            with TabPane("✚ DAYGNOSTICS", id="diagnostics"):
                yield Static("Local checks — configuration is not changed.", classes="note")
                yield DataTable(id="health-table", cursor_type="row", zebra_stripes=True)
                yield Static("For external DNS/TLS checks: repocache health --deep", classes="panel")
        yield Footer()

    def on_mount(self) -> None:
        repo_table = self.query_one("#repo-table", DataTable)
        repo_table.add_columns("Repository", "Location", "Upstream")
        proposal_table = self.query_one("#proposal-table", DataTable)
        proposal_table.add_columns("Proposal ID", "OS", "Type", "Upstream host", "Transport")
        health_table = self.query_one("#health-table", DataTable)
        health_table.add_columns("Check", "Status", "Details")
        self.poll(force=True)
        self._next_auto_at = time.monotonic() + self.refresh_intervals[self.refresh_interval_index]
        self.set_interval(1.0, self._auto_tick)

    def _auto_tick(self) -> None:
        if self.refresh_enabled and time.monotonic() >= self._next_auto_at and not self._busy:
            self._next_auto_at = time.monotonic() + self.refresh_intervals[self.refresh_interval_index]
            self.poll()

    def poll(self, force: bool = False) -> None:
        if not self._busy:
            self._busy = True
            self._collect(force)

    @work(thread=True, exclusive=True)
    def _collect(self, force: bool = False) -> None:
        try:
            age = time.monotonic() - self._cached_at
            if force or not self._cached or age >= 60:
                data = snapshot(self.settings, hours=self.periods[self.period_index])
                diagnostics = health(self.settings, deep=False)
                self._cached = data
                self._cached_at = time.monotonic()
            else:
                data = dict(self._cached)
                data["service"] = service_status()
                data["disk"] = disk_status(self.settings.cache_dir)
                data["metrics"] = metrics(self.settings, hours=self.periods[self.period_index])
                diagnostics = None
            if self._metrics_filter is not None:
                data = dict(data)
                data["metrics"] = metrics(
                    self.settings, hours=self.periods[self.period_index],
                    repo=self._metrics_filter)
            try:
                lines, _ = _tail_bytes(self.settings.metrics_log, max_bytes=40_000)
                activity = [self._short_event(line) for line in lines[-7:]]
            except OSError:
                activity = ["Cannot access the metrics log"]
            self.call_from_thread(self._present, data, diagnostics, activity)
        except Exception as error:
            self.call_from_thread(self._error, str(error))

    @staticmethod
    def _short_event(line: str) -> str:
        """Display only validated telemetry fields; raw requests can contain secrets."""
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                stamp = timestamp(obj.get("time_iso8601") or obj.get("timestamp") or obj.get("time"))
                when = stamp.strftime("%H:%M:%S") if stamp else "?"
                raw_code = str(obj.get("status") or obj.get("http_status") or "")
                code = raw_code if (len(raw_code) == 3 and raw_code.isascii()
                                    and raw_code.isdigit() and 100 <= int(raw_code) <= 599) else "?"
                raw_cache = str(obj.get("upstream_cache_status") or obj.get("cache_status") or "")
                cache = raw_cache.upper() if raw_cache.upper() in {
                    "HIT", "MISS", "BYPASS", "EXPIRED", "STALE",
                    "UPDATING", "REVALIDATED"
                } else "-"
                return f"{when:8}  {code:3}  {cache:10}"
        except (ValueError, TypeError):
            pass
        return "Malformed log record (details suppressed)"

    def _error(self, message: str) -> None:
        self._busy = False
        # Exception messages can contain Rich tags, which Textual treats as markup.
        # Escaping prevents a second exception in the error notification.
        self.notify("Failed to collect data: " + escape(message[:120]), severity="error")

    def _present(self, data: Dict[str, Any], diagnostics: Any, activity: List[str]) -> None:
        self._busy = False
        self._latest = data
        m = data["metrics"]
        disk = data["disk"]
        status = data["service"]
        pct = m["hit_rate"]
        self.query_one("#kpi-nginx", Static).update(safe_markup(
            f"[dim]NGINX SERVICE[/dim]\n[bold {'green' if status == 'active' else 'yellow'}]{escape(status.upper())}[/]\n[dim]systemd[/dim]"))
        self.query_one("#kpi-hit", Static).update(safe_markup(
            f"[dim]CACHE HIT · {self.period_labels[self.period_index]}[/dim]\n[bold cyan]{pct if pct is not None else 'N/A'}{'%' if pct is not None else ''}[/]\n[dim]requests with cache_status[/dim]"))
        self.query_one("#kpi-requests", Static).update(safe_markup(
            f"[dim]REQUESTS · SAMPLE[/dim]\n[bold #75bfff]{m['requests'] if m['available'] else 'N/A'}[/]\n[dim]log NDJSON[/dim]"))
        self.query_one("#kpi-repos", Static).update(safe_markup(
            f"[dim]REPOSITORIES[/dim]\n[bold #65e2c3]{len(data['repos']) if data['nginx_config_readable'] else 'N/A'}[/]\n[dim]locations proxy_pass[/dim]"))
        if disk["ok"]:
            info = f"[bold cyan]CACHE DISK[/bold cyan]\n{human_bytes(disk['used'])} / {human_bytes(disk['total'])}\n"
            info += f"Usage: {disk['percent']}%\n"
            info += "[dim]Entire filesystem, not just cache files[/dim]"
        else:
            info = "[yellow]Disk unavailable[/yellow]\n" + escape(str(disk.get("reason", "")))
        self.query_one("#disk", Static).update(safe_markup(info))
        cache_info = (f"[bold cyan]CACHE STATISTICS[/bold cyan]\n"
                      f"HIT: {m['hit']}  |  MISS: {m['miss']}  |  BYPASS: {m.get('bypass', 0)}\n"
                      f"HTTP 5xx: {m['errors_5xx'] if m['available'] else 'N/A'}\n"
                      f"[dim]Other cache statuses are included in the HIT-rate denominator[/dim]")
        self.query_one("#cache", Static).update(safe_markup(cache_info))
        series = [float(x["requests"]) for x in m["series"]] if m["available"] else None
        self.query_one("#requests-graph", Sparkline).data = series
        self.query_one("#histogram", Sparkline).data = series
        granularity = "DAY" if m["series_unit"] == "day" else "HOUR"
        scope = "ALL ROUTES" if self._metrics_filter is None else self._metrics_filter
        title = f"REQUESTS/{granularity} · UTC · {self.period_labels[self.period_index]} · {scope}"
        if not m["available"]:
            title += "  — N/A (no samples)"
        self.query_one("#requests-title", Static).update(title)
        self.query_one("#metric-title", Static).update(title)
        metric_info = (f"[bold cyan]METRICS · Last {self.period_labels[self.period_index]} · {escape(scope)}[/]\n"
                       f"Requests (sample): {m['requests'] if m['available'] else 'N/A'}    "
                       f"HIT rate: {str(m['hit_rate']) + '%' if m['hit_rate'] is not None else 'N/A'}\n"
                       f"HIT: {m['hit']}    MISS: {m['miss']}    BYPASS: {m.get('bypass', 0)}\n"
                       f"5xx: {m['errors_5xx'] if m['errors_5xx'] is not None else 'N/A'}    "
                       f"Bytes served*: {human_bytes(m['bytes_sent']) if m['available'] else 'N/A'}\n"
                       f"Average duration*: {str(m['avg_request_ms']) + ' ms' if m['avg_request_ms'] is not None else 'N/A'}\n"
                       "[dim]* Only fields present in the log[/dim]")
        self.query_one("#metric-info", Static).update(safe_markup(metric_info))
        period_note = ("[bold]Observed time range[/bold]\n" +
                       f"First record: {escape(m['first_seen'] or 'N/A')}\n"
                       f"Last record: {escape(m['last_seen'] or 'N/A')}\n"
                       f"Sample quality: {escape(m.get('coverage', 'unknown'))}\n" +
                       f"[dim]{escape(m['detail'])}[/dim]" +
                       ("\n[yellow]Sample truncated to 8 MB![/yellow]" if m["truncated"] else ""))
        self.query_one("#metric-details", Static).update(safe_markup(period_note))
        output = Text("RECENT REQUESTS · JSON log\n", style="bold cyan")
        for item in activity:
            output.append("".join(ch for ch in item if ch.isprintable()) + "\n", style="dim white")
        if len(activity) == 0:
            output.append("No log entries", style="yellow")
        self.query_one("#activity", Static).update(output)
        rows = self.query_one("#repo-table", DataTable)
        if data["nginx_config_readable"]:
            source = data["nginx_config_source"]
            validation = "validated configuration" if data["nginx_config_validated"] else "configuration read (syntax not validated)"
            extra = " · some files unreadable" if data["nginx_config_partial"] else ""
            note = f"Source: {source} · {validation}{extra}. {len(data['repos'])} proxy_pass routes found."
            if not data["repos"]:
                note += " Check whether NGINX uses locations, maps or dynamic upstreams."
        else:
            note = "Configuration unavailable (read permissions or nginx -T). Run sudo repocache repos list."
        self.query_one("#repo-note", Static).update(note)
        if data["repos"] != self._all_repos:
            previous = {item["path"]: item["upstream"] for item in self._all_repos}
            self._probe_results = {path: result for path, result in self._probe_results.items()
                                   if any(r["path"] == path and previous.get(path) == r["upstream"]
                                          for r in data["repos"])}
            rows.clear()
            self._all_repos = data["repos"]
            for repo in data["repos"]:
                rows.add_row(Text(repo["name"]), Text(repo["path"]), Text(repo["upstream"]), key=repo["path"])
        if not data["repos"]:
            self._selected_repo = ""
            self.query_one("#repo-detail", Static).update("No proxy_pass routes detected. Check the discovery source; no placeholder repositories were created.")
        if diagnostics is not None:
            diagnostic_table = self.query_one("#health-table", DataTable)
            diagnostic_table.clear()
            for item in diagnostics["checks"]:
                color = "green" if item["result"] == "OK" else ("red" if item["result"] == "FAIL" else "yellow")
                diagnostic_table.add_row(Text(item["name"]), Text(item["result"], style=color), Text(item["detail"]))
        mode = (f"AUTO {self.refresh_intervals[self.refresh_interval_index]}s"
                if self.refresh_enabled else "MANUAL")
        self.sub_title = f"{status.upper()} · {mode} · updated at {datetime.now().astimezone().strftime('%H:%M:%S')} · P: period"

    def _selected(self) -> Dict[str, str] | None:
        return next((item for item in self._all_repos
                     if item["path"] == self._selected_repo), None)

    def _show_selected(self) -> None:
        selected = self._selected()
        if selected is None:
            return
        info = Text("REPOSITORY  ", style="bold cyan")
        info.append(selected["name"] + "\n")
        info.append("Configured: yes    NGINX validation: " +
                    ("validated" if self._latest.get("nginx_config_validated")
                     else "not verified") + "\n")
        info.append("Location: " + selected["path"] + "\n")
        info.append("Upstream: " + selected["upstream"] + "\n")
        info.append("Discovery: " + str(self._latest.get("nginx_config_source", "unknown")) + "\n")
        info.append("Press F to show filtered metrics for this repository.\n")
        info.append("Recently active (24h log sample): " +
                    self._repo_activity.get(selected["path"], "unknown") + "\n")
        probe = self._probe_results.get(selected["path"])
        if probe is None:
            info.append("Reachability: not tested; press T to probe DNS/TCP/TLS\n", style="yellow")
        else:
            info.append("Reachability: " + probe["result"] + " — " + probe["detail"] + "\n")
            info.append("DNS: " + probe["dns"] + " · TCP: " + probe["connectivity"] +
                        " · TLS: " + probe["tls"])
        self.query_one("#repo-detail", Static).update(info)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "proposal-table":
            ident = str(event.row_key.value)
            if ident in self._proposal_versions:
                self._selected_proposal = ident
                self._review_confirmation = None
                self.query_one("#proposal-detail", Static).update(
                    "Selected proposal " + ident[:12] +
                    ". Review = Y twice, reject = N twice. Neither action publishes a route.")
            return
        if event.data_table.id != "repo-table":
            return
        selected = next((item for item in self._all_repos
                         if item["path"] == str(event.row_key.value)), None)
        if selected is not None:
            self._selected_repo = selected["path"]
            self._show_selected()
            self._collect_repo_activity(selected["path"])

    @work(thread=True)
    def _collect_repo_activity(self, path: str) -> None:
        try:
            report = metrics(self.settings, hours=24, repo=path)
            if report["available"] and report["requests"]:
                result = "yes; last observed " + str(report.get("last_seen", "unknown"))
            elif self.settings.metrics_log.is_file():
                result = "not observed (limited log sample)"
            else:
                result = "unknown (metrics log unavailable)"
        except OSError:
            result = "unknown (metrics log inaccessible)"
        self.call_from_thread(self._present_repo_activity, path, result)

    def _present_repo_activity(self, path: str, result: str) -> None:
        self._repo_activity[path] = result
        if self._selected_repo == path:
            self._show_selected()

    def action_probe_selected(self) -> None:
        selected = self._selected()
        if selected is None:
            self.notify("Select a repository before probing an upstream.", severity="warning")
            return
        self.notify("Probing selected upstream (bounded DNS/TCP/TLS checks)…")
        self._probe_selected_upstream(dict(selected))

    @work(thread=True)
    def _probe_selected_upstream(self, repo: Dict[str, str]) -> None:
        result = probe_upstream(repo, timeout=5)
        self.call_from_thread(self._present_repo_probe, repo["path"], result)

    def _present_repo_probe(self, path: str, result: Dict[str, str]) -> None:
        self._probe_results[path] = result
        if self._selected_repo == path:
            self._show_selected()
            self.notify("Upstream check: " + result["result"],
                        severity="information" if result["result"] == "OK" else "warning")

    def action_refresh(self) -> None:
        self._next_auto_at = time.monotonic() + self.refresh_intervals[self.refresh_interval_index]
        self.poll(force=True)

    def action_toggle_auto(self) -> None:
        self.refresh_enabled = not self.refresh_enabled
        self._next_auto_at = time.monotonic() + self.refresh_intervals[self.refresh_interval_index]
        self.notify(("Auto-refresh enabled" if self.refresh_enabled else "Manual mode") +
                    f" · {self.refresh_intervals[self.refresh_interval_index]}s", timeout=2)
        self._update_refresh_subtitle()

    def action_refresh_interval(self) -> None:
        self.refresh_interval_index = (self.refresh_interval_index + 1) % len(self.refresh_intervals)
        self._next_auto_at = time.monotonic() + self.refresh_intervals[self.refresh_interval_index]
        self.notify(f"Refresh interval: {self.refresh_intervals[self.refresh_interval_index]}s", timeout=2)
        self._update_refresh_subtitle()

    def _update_refresh_subtitle(self) -> None:
        mode = (f"AUTO {self.refresh_intervals[self.refresh_interval_index]}s" if self.refresh_enabled else "MANUAL")
        self.sub_title = f"{self._latest.get('service', 'N/A').upper()} · {mode} · P: period"

    def _refresh_submissions(self) -> None:
        table = self.query_one("#proposal-table", DataTable)
        table.clear()
        self._selected_proposal = ""
        self._review_confirmation = None
        self._proposal_versions = {}
        label = self.query_one("#proposal-note", Static)
        if os.geteuid() != 0:
            label.update("Administrator OS identity required (root). No proposals shown.")
            return
        if not SUBMISSION_QUEUE_PATH.is_file() or SUBMISSION_QUEUE_PATH.is_symlink():
            label.update("No trusted submission queue configured. Intake remains disabled.")
            return
        try:
            proposals = SubmissionQueue(SUBMISSION_QUEUE_PATH).pending()
            self._proposal_versions = {p["id"]: p["version"] for p in proposals}
            for proposal in proposals:
                # Only show the canonical URL's host, not query strings, paths or
                # original payloads. Client credentials are never part of the queue.
                first = proposal["repositories"][0]
                host = urlsplit(first["url"]).hostname or "invalid"
                table.add_row(proposal["id"][:12], proposal["os"] + " " +
                              proposal["version_os"], first["type"], host,
                              "HTTP (review)" if first["insecure_http"] else "HTTPS",
                              key=proposal["id"])
            label.update(f"{len(proposals)} pending proposal(s). Only the first origin per proposal is shown.")
        except (SubmissionError, OSError, ValueError):
            label.update("Cannot access trusted submission queue; no decisions permitted.")

    def _decide(self, action: str) -> None:
        if (self.query_one(TabbedContent).active != "submissions" or
                os.geteuid() != 0):
            self.notify("Administrator review is unavailable.", severity="warning")
            return
        ident = self._selected_proposal
        if not ident or ident not in self._proposal_versions:
            self.notify("Select a pending proposal first.", severity="warning")
            return
        if self._review_confirmation != (ident, action):
            self._review_confirmation = (ident, action)
            self.notify("Press the same action again to confirm. Review does not publish.", severity="warning")
            return
        version = self._proposal_versions[ident]
        self._review_confirmation = None
        try:
            SubmissionQueue(SUBMISSION_QUEUE_PATH).decide(ident, action, expected_version=version)
        except (SubmissionError, OSError, ValueError):
            self.notify("Review could not be completed; refresh the queue.", severity="error")
            return
        self._last_review = (ident, version + 1)
        self.notify("Decision recorded in local audit; no route was published.")
        self._refresh_submissions()

    def action_review_selected(self) -> None:
        self._decide("review")

    def action_reject_selected(self) -> None:
        self._decide("reject")

    def action_undo_review(self) -> None:
        if (os.geteuid() != 0 or self.query_one(TabbedContent).active != "submissions"
                or self._last_review is None):
            self.notify("No authorized decision to undo.", severity="warning")
            return
        ident, version = self._last_review
        self._last_review = None
        try:
            SubmissionQueue(SUBMISSION_QUEUE_PATH).decide(
                ident, "reopen", expected_version=version)
            self.notify("Proposal reopened; audit trail retained.")
        except (SubmissionError, OSError, ValueError):
            self.notify("Cannot undo this decision; review the audit.", severity="error")
        self._refresh_submissions()

    def action_filter_selected_metrics(self) -> None:
        selected = self._selected()
        if selected is None:
            self.notify("Select an approved repository route first.", severity="warning")
            return
        self._metrics_filter = selected["path"]
        self.query_one(TabbedContent).active = "metrics"
        self.poll(force=True)

    def action_global_metrics(self) -> None:
        self._metrics_filter = None
        self.query_one(TabbedContent).active = "metrics"
        self.poll(force=True)

    def action_tab(self, pane: str) -> None:
        self.query_one(TabbedContent).active = pane
        if pane == "submissions":
            self._refresh_submissions()

    def action_period(self) -> None:
        self.period_index = (self.period_index + 1) % len(self.periods)
        self.poll(force=True)
