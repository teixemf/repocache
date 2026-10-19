"""REPOCACHE server command-line interface."""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn
from rich.table import Table
from rich.text import Text

from repocache import __version__
from repocache.core import (
    Settings, check_upstream, command, discover_repos, disk_status, health as health_report,
    metrics as metrics_report, nginx_config, service_status, snapshot, _tail_bytes,
)

app = typer.Typer(help="REPOCACHE Control Center | NGINX proxy CLI/TUI management",
                  add_completion=True, rich_markup_mode="rich", invoke_without_command=True)
repos_app = typer.Typer(help="Inspect and test repositories", no_args_is_help=True)
cache_app = typer.Typer(help="Inspect cache and storage", no_args_is_help=True)
logs_app = typer.Typer(help="Read and follow logs", no_args_is_help=True)
service_app = typer.Typer(help="NGINX status and safe operations", no_args_is_help=True)
update_app = typer.Typer(help="Discover trusted GitHub Releases and manage server upgrades", no_args_is_help=False)
config_app = typer.Typer(help="Configuration checks and discovery", no_args_is_help=True)
catalog_app = typer.Typer(help="Explicitly approved read-only repository catalog", no_args_is_help=True)
app.add_typer(repos_app, name="repos")
app.add_typer(cache_app, name="cache")
app.add_typer(logs_app, name="logs")
app.add_typer(service_app, name="service")
app.add_typer(config_app, name="config")
app.add_typer(catalog_app, name="catalog")
app.add_typer(update_app, name="update")
console = Console()


def settings() -> Settings:
    return Settings()


def emit_json(data: Dict[str, Any]) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2, default=str))


def human_bytes(value: Any) -> str:
    if value is None:
        return "N/A"
    amount = float(value)
    for unit in ["B", "KiB", "MiB", "GiB", "TiB"]:
        if abs(amount) < 1024 or unit == "TiB":
            return f"{amount:.1f} {unit}"
        amount /= 1024
    return "N/A"


def indicator(value: str) -> Text:
    color = "green" if value in {"OK", "active"} else ("red" if value in {"FAIL", "failed"} else "yellow")
    return Text(value, style=f"bold {color}")


def tui_launch(auto_refresh: bool = True, interval: int = 15) -> None:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        console.print("[yellow]The TUI requires an interactive terminal. Run 'repocache status'.[/yellow]")
        raise typer.Exit(2)
    try:
        from repocache.tui import RepoCacheApp
    except ImportError as error:
        console.print(f"[red]Textual is unavailable: {error}[/red]")
        console.print("Reinstall the package with ./install.sh.")
        raise typer.Exit(2)
    RepoCacheApp(auto_refresh=auto_refresh, refresh_interval=interval).run()


@app.callback()
def main(ctx: typer.Context,
         version: bool = typer.Option(False, "--version", help="Show the version", is_eager=True)) -> None:
    if version:
        console.print(f"REPOCACHE Control Center {__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        if sys.stdout.isatty() and sys.stdin.isatty():
            tui_launch()
        else:
            show_status(json_output=True)


@app.command("dashboard")
def dashboard(auto: bool = typer.Option(True, "--auto/--no-auto", help="Refresh automatically"),
              interval: int = typer.Option(15, "--interval", help="5, 15, 30 or 60 seconds")) -> None:
    """Open the interactive terminal/SSH dashboard."""
    if interval not in (5, 15, 30, 60):
        raise typer.BadParameter("Interval must be 5, 15, 30 or 60 seconds")
    tui_launch(auto_refresh=auto, interval=interval)


@app.command("status")
def show_status(json_output: bool = typer.Option(False, "--json", help="JSON format")) -> None:
    """Show NGINX, repository, disk and metrics status."""
    report = snapshot(settings())
    if json_output:
        emit_json(report)
        return
    table = Table(title="◈ REPOCACHE · Overview", border_style="cyan")
    table.add_column("Component", style="cyan", no_wrap=True)
    table.add_column("Status / value")
    table.add_row("NGINX service", indicator(report["service"]))
    table.add_row("Proxy repositories", str(len(report["repos"])) if report["nginx_config_readable"] else "N/A (nginx -T failed)")
    disk = report["disk"]
    table.add_row("Cache disk", f"{human_bytes(disk['used'])} / {human_bytes(disk['total'])} (FS)" if disk["ok"] else "N/A")
    m = report["metrics"]
    table.add_row("Requests (24h sample)", str(m["requests"]) if m["available"] else "N/A")
    table.add_row("Cache HIT (24h sample)", f"{m['hit_rate']}%" if m["hit_rate"] is not None else "N/A")
    table.add_row("Metrics source", str(settings().metrics_log))
    table.add_row("NGINX discovery", report["nginx_config_source"] +
                  (" (not validated)" if not report["nginx_config_validated"] else ""))
    console.print(table)
    console.print("[dim]Note: disk usage covers the filesystem; metrics reflect a limited JSON log sample.[/dim]")


@repos_app.command("list")
def repos_list(json_output: bool = typer.Option(False, "--json")) -> None:
    """Discover proxy_pass routes (nginx -T or direct include-file reads)."""
    data = nginx_config(settings())
    repos = discover_repos(data["stdout"])
    if json_output:
        emit_json({"ok": data["ok"], "validated": data["validated"],
                   "source": data["source"], "partial": data["partial"],
                   "warnings": data["warnings"], "repos": repos,
                   "error": data["stderr"] if not data["validated"] else ""})
        return
    if data["ok"] and not data["validated"]:
        console.print(Text(f"Discovered via {data['source']}; nginx did NOT validate this configuration.", style="yellow"))
    elif not data["ok"]:
        console.print(Text("Could not read configuration: " +
                           (data["stderr"] or "; ".join(data["warnings"])), style="yellow"))
    if data["partial"]:
        console.print(Text("Warning: only some NGINX include files could be read.", style="yellow"))
    table = Table(title="◈ Configured repositories", border_style="blue")
    table.add_column("Name", style="cyan")
    table.add_column("Location")
    table.add_column("proxy_pass")
    for repo in repos:
        table.add_row(repo["name"], repo["path"], repo["upstream"])
    console.print(table)
    if not repos:
        console.print("[yellow]No proxy_pass locations found. The configuration may use dynamic upstreams or be inaccessible.[/yellow]")


def find_repo(name: str) -> Dict[str, str]:
    result = nginx_config(settings())
    repos = discover_repos(result["stdout"])
    matches = [item for item in repos if item["name"] == name or item["path"] == name]
    if not matches:
        console.print(f"[red]Repository '{name}' not found.[/red]")
        if not result["ok"]:
            console.print(f"[yellow]nginx -T: {result['stderr']}[/yellow]")
        raise typer.Exit(1)
    return matches[0]


@repos_app.command("info")
def repo_info(name: str) -> None:
    """Show a repository location and its upstream."""
    repo = find_repo(name)
    table = Table(title=repo["name"], show_header=False)
    for label, key in [("Location", "path"), ("Upstream", "upstream")]:
        table.add_row(label, Text(repo[key]))
    console.print(table)


@repos_app.command("test")
def repo_test(name: str, json_output: bool = typer.Option(False, "--json")) -> None:
    """Test upstream DNS, HTTP and TLS; does NOT test the local proxy end to end."""
    repo = find_repo(name)
    result = check_upstream(repo)
    data = {"repo": repo, **result}
    if json_output:
        emit_json(data)
    else:
        console.print(Panel(f"[{('green' if result['result']=='OK' else 'yellow' if result['result']=='WARN' else 'red')}]{result['result']}[/] — {result['detail']}", title="Upstream diagnostics"))
        console.print("[dim]This test contacts the upstream; it does not verify the local proxy route.[/dim]")
    if result["result"] == "FAIL":
        raise typer.Exit(1)


@cache_app.command("stats")
def cache_stats(json_output: bool = typer.Option(False, "--json")) -> None:
    """Show filesystem usage for the cache mount (not cache file sizes)."""
    data = disk_status(settings().cache_dir)
    if json_output:
        emit_json(data)
        return
    if not data["ok"]:
        console.print(f"[red]{data.get('reason', 'Unavailable')}[/red]")
        raise typer.Exit(1)
    used, total = human_bytes(data["used"]), human_bytes(data["total"])
    console.print(Panel(f"[cyan]{data['path']}[/cyan]\n{used} of {total} used ({data['percent']}%)\n"
                        f"[dim]{data['note']}[/dim]", title="Storage", border_style="cyan"))


def parse_period(period: str) -> int:
    options = {"1h": 1, "6h": 6, "24h": 24, "7d": 168, "30d": 720}
    if period not in options:
        raise typer.BadParameter("Use: 1h, 6h, 24h, 7d or 30d")
    return options[period]


@app.command("metrics")
def show_metrics(period: str = typer.Option("24h", "--period", "-p", help="1h / 6h / 24h / 7d / 30d"),
                 repo: Optional[str] = typer.Option(None, "--repo", help="Filter by repository path"),
                 json_output: bool = typer.Option(False, "--json")) -> None:
    """Display request statistics and histogram from JSON logs."""
    data = metrics_report(settings(), hours=parse_period(period), repo=repo)
    if json_output:
        emit_json(data)
        return
    if not data["available"]:
        console.print(Panel(data["detail"], title="Metrics unavailable", border_style="yellow"))
        return
    table = Table(title=f"◈ Metrics · {period} (log sample)", border_style="cyan", show_header=False)
    for label, value in [("Requests", str(data["requests"])), ("Cache HIT", str(data["hit"])),
                         ("Cache MISS", str(data["miss"])), ("Cache BYPASS", str(data.get("bypass", 0))),
                         ("Sample quality", data.get("coverage", "unknown")),
                         ("HIT rate", f"{data['hit_rate']}%" if data["hit_rate"] is not None else "N/A"),
                         ("HTTP 5xx", str(data["errors_5xx"]) if data["errors_5xx"] is not None else "N/A"),
                         ("Bytes served (when recorded)", human_bytes(data["bytes_sent"])),
                         ("Average request time", f"{data['avg_request_ms']} ms" if data["avg_request_ms"] is not None else "N/A")]:
        table.add_row(label, value)
    console.print(table)
    rows = data["series"]
    if rows:
        nonzero = max(row["requests"] for row in rows)
        unit = "day (UTC, partial boundary days)" if data["series_unit"] == "day" else "hour · UTC"
        graph = Table(title=f"Requests / {unit}", show_header=False, box=None)
        for row in rows[-32:] if data["series_unit"] == "day" else rows[-24:]:
            count = row["requests"]
            bar_size = round(count / nonzero * 25) if nonzero else 0
            label = row["hour"][5:10] if data["series_unit"] == "day" else row["hour"][5:16].replace("T", " ")
            graph.add_row(label, Text("█" * bar_size, style="cyan"), str(count))
        console.print(graph)
    console.print(f"[dim]{data['detail']}[/dim]")
    if data["truncated"]:
        console.print("[yellow]Log truncated to the last 8 MB; history may be incomplete.[/yellow]")


@app.command("health")
def health(deep: bool = typer.Option(False, "--deep", help="Include external upstream probes"),
           json_output: bool = typer.Option(False, "--json")) -> None:
    """Check NGINX, logs and cache; --deep performs external requests."""
    data = health_report(settings(), deep=deep)
    if json_output:
        emit_json(data)
    else:
        table = Table(title="◈ REPOCACHE Diagnostics", border_style="cyan")
        table.add_column("Check", style="cyan")
        table.add_column("Result")
        table.add_column("Details")
        for item in data["checks"]:
            table.add_row(item["name"], indicator(item["result"]), Text(item["detail"] or "-"))
        console.print(table)
        if deep:
            console.print("[dim]Upstream probes do not verify access through the REPOCACHE address.[/dim]")
    if not data["ok"]:
        raise typer.Exit(1)


@logs_app.command("tail")
def logs_tail(lines: int = typer.Option(15, "--lines", "-n", min=1, max=200),
              json_output: bool = typer.Option(False, "--json")) -> None:
    """Display the last NDJSON lines from the metrics log."""
    path = settings().metrics_log
    try:
        content, _ = _tail_bytes(path)
    except OSError as error:
        console.print(f"[red]Read error: {error}[/red]")
        raise typer.Exit(1)
    selected = content[-lines:]
    if json_output:
        emit_json({"lines": selected, "path": str(path)})
    else:
        for line in selected:
            try:
                value = json.loads(line)
                console.print_json(json.dumps(value, ensure_ascii=False))
            except ValueError:
                console.print(Text(line))


@logs_app.command("follow")
def logs_follow() -> None:
    """Follow the log (including rotation); press Ctrl+C to stop."""
    path = settings().metrics_log
    console.print(f"[cyan]Following {path}[/cyan] — Ctrl+C to quit")
    stream = None
    try:
        while True:
            try:
                stat = path.stat()
                if stream is None or os.fstat(stream.fileno()).st_ino != stat.st_ino:
                    if stream:
                        stream.close()
                    stream = path.open("r", encoding="utf-8", errors="replace")
                    stream.seek(0, os.SEEK_END)
                line = stream.readline()
                if line:
                    console.print(Text(line.rstrip("\n")))
                else:
                    if stream.tell() > stat.st_size:
                        stream.seek(0)
                    time.sleep(0.3)
            except FileNotFoundError:
                if stream:
                    stream.close()
                    stream = None
                time.sleep(1)
    except KeyboardInterrupt:
        return
    except PermissionError as error:
        console.print(f"[red]Read error: {error}[/red]")
        raise typer.Exit(1)
    finally:
        if stream:
            stream.close()


@service_app.command("status")
def service_show() -> None:
    """Show NGINX status via systemctl."""
    state = service_status()
    console.print("NGINX service:", indicator(state))
    if state != "active":
        raise typer.Exit(1)


@service_app.command("reload")
def service_reload(yes: bool = typer.Option(False, "--yes", help="Confirm reload")) -> None:
    """Run nginx -t before reloading the NGINX service."""
    console.print("[yellow]Operation: nginx -t → systemctl reload nginx[/yellow]")
    if not yes and not typer.confirm("Reload the NGINX service?", default=False):
        console.print("Cancelled; no changes made.")
        return
    result = command([settings().nginx_bin, "-t"], timeout=12)
    if not result["ok"]:
        console.print(f"[red]Invalid NGINX configuration. Reload skipped. {result['stderr']}[/red]")
        raise typer.Exit(1)
    result = command(["systemctl", "reload", "nginx"], timeout=15)
    if result["ok"]:
        console.print("[green]Reload completed successfully.[/green]")
    else:
        console.print(f"[red]Reload failed: {result['stderr']}[/red]")
        raise typer.Exit(1)


@config_app.command("check")
def config_check() -> None:
    """Run nginx -t without modifying configuration."""
    result = command([settings().nginx_bin, "-t"], timeout=12)
    console.print(Text(result["stderr"] or result["stdout"]))
    if not result["ok"]:
        raise typer.Exit(1)


@config_app.command("show")
def config_show() -> None:
    """Show configuration sources and paths (without credentials)."""
    config = settings()
    table = Table(show_header=False, title="REPOCACHE data sources")
    table.add_row("Cache", str(config.cache_dir))
    table.add_row("Metrics", str(config.metrics_log))
    table.add_row("NGINX executable", str(config.nginx_bin))
    table.add_row("Repository discovery", "nginx -T, with direct-file fallback" if not config.nginx_dump_file else config.nginx_dump_file)
    table.add_row("NGINX configuration file", str(config.nginx_conf))
    console.print(table)



def _update_exit(result: Dict[str, Any]) -> None:
    """0=discovery succeeded, 2=authentication, 3=offline, 4=invalid, 5=error."""
    codes = {"authentication-required": 2, "offline": 3,
             "invalid-release": 4, "error": 5}
    if result["status"] in codes:
        raise typer.Exit(codes[result["status"]])


@update_app.command("check")
def update_check(json_output: bool = typer.Option(False, "--json")) -> None:
    """Check installed versus latest verified stable GitHub release (read-only)."""
    from repocache.updater import check
    result = check()
    if json_output:
        print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    else:
        console.print(Text(
            f"Installed: {result['installed_version']} · Latest: {result['latest_version'] or 'unknown'}"
            f" · {result['status']} · {result['message']}"
        ))
    _update_exit(result)


@update_app.command("list")
def update_list(json_output: bool = typer.Option(False, "--json")) -> None:
    """List published stable release assets and conservative compatibility."""
    from repocache.updater import list_versions
    result = list_versions()
    if json_output:
        emit_json(result)
    else:
        if result["releases"]:
            table = Table(title="◈ REPOCACHE · GitHub Releases")
            table.add_column("Version")
            table.add_column("Installed")
            table.add_column("Latest")
            table.add_column("Compatibility")
            for release in result["releases"]:
                table.add_row(release["version"], "yes" if release["installed"] else "",
                              "yes" if release["latest"] else "",
                              release["compatibility"] + ": " + release["compatibility_reason"])
            console.print(table)
        else:
            console.print(Text(result["status"] + " · " + result["message"], style="yellow"))
        if not any(x["installed"] for x in result["releases"]):
            console.print("Installed locally: " + result["installed_version"] + " (not in discoverable releases)")
    _update_exit(result)


@update_app.callback(invoke_without_command=True)
def update_main(ctx: typer.Context,
                version: Optional[str] = typer.Option(
                    None, "--version", help="Install the selected stable X.Y.Z release"),
                bundle: Optional[Path] = typer.Option(
                    None, "--bundle", help="Use an already obtained local tar.gz bundle"),
                checksum: Optional[Path] = typer.Option(
                    None, "--checksum", help="Matching local SHA-256 checksum file"),
                manifest: Optional[Path] = typer.Option(
                    None, "--manifest", help="Publisher-signed release manifest"),
                signature: Optional[Path] = typer.Option(
                    None, "--signature", help="Detached Ed25519 manifest signature"),
                wheels: Optional[Path] = typer.Option(
                    None, "--wheelhouse", help="Signed, hash-pinned offline dependencies"),
                yes: bool = typer.Option(
                    False, "--yes", help="Non-interactive acknowledgement (no prompts)"),
                json_output: bool = typer.Option(False, "--json", help="JSON status")) -> None:
    """Install a compatible, verified release; refuse uncertain downgrades."""
    if ctx.invoked_subcommand is not None:
        return
    from repocache.updater import apply, UpdateError, UpdateBusyError
    from repocache.releases import DiscoveryError
    try:
        result = apply(version=version, bundle=bundle, checksum=checksum,
                       manifest=manifest, signature=signature, wheels=wheels)
    except (UpdateError, DiscoveryError, OSError) as exc:
        status = ("busy" if isinstance(exc, UpdateBusyError) else
                  exc.status if isinstance(exc, DiscoveryError) else "error")
        response = {"ok": False, "status": status, "error": str(exc),
                    "performed": False, "retryable": status == "busy"}
        if json_output:
            emit_json(response)
        else:
            console.print(Text("Update refused: " + str(exc), style="red"))
        raise typer.Exit(75 if status == "busy" else 2)
    if json_output:
        emit_json(result)
    else:
        console.print(f"REPOCACHE {result['version']}: {result['status']} "
                      f"(previously {result['previous_version']})")


@catalog_app.command("publish")
def catalog_publish(
        server: str = typer.Option(..., "--server", help="Public HTTPS origin of this cache server"),
        approvals: Path = typer.Option(..., "--approvals", help="Administrator-reviewed JSON allowlist"),
        output: Path = typer.Option(..., "--output", help="Static catalog.json file to replace"),
        json_output: bool = typer.Option(False, "--json", help="Machine-readable output")) -> None:
    """Atomically export approved HTTPS routes without changing NGINX."""
    from repocache.catalog import CatalogError, build_catalog, load_approvals, publish_catalog
    try:
        approved = load_approvals(approvals)
        data = build_catalog(nginx_config(settings()), approved, server)
        publish_catalog(data, output)
    except (CatalogError, OSError) as exc:
        if json_output:
            emit_json({"ok": False, "error": str(exc)})
        else:
            console.print("[red]Catalog not published: " + str(exc) + "[/red]")
        raise typer.Exit(2)
    result = {"ok": True, "schema": data["schema"],
              "published_repositories": len(data["repositories"]), "output": str(output)}
    if json_output:
        emit_json(result)
    else:
        console.print(f"[green]Published {result['published_repositories']} approved routes to {output}[/green]")


if __name__ == "__main__":
    app()
