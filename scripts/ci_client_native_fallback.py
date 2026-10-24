#!/usr/bin/env python3
"""Isolated, executable APT/DNF HTTP metadata failover probe (#24).

This experiment runs ONLY in disposable Debian 13/AlmaLinux 10 containers.
It does not configure a production REPOCACHE host, disable repository signing
or prove package download, installation, real TLS or power-loss behavior.

Exit nonzero if native metadata preference/fallback/recovery fails. Record
manager version and local HTTP request counts for reproducible evidence.
"""
from __future__ import annotations

import argparse
import email.utils
import gzip
import hashlib
import http.server
import lzma
import os
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path


class HTTPBackend:
    def __init__(self, files: Path):
        self.mode = "healthy"
        self.hits: list[str] = []

        class Handler(http.server.SimpleHTTPRequestHandler):
            def do_GET(handler):
                self.hits.append(handler.path)
                if self.mode != "healthy":
                    handler.send_error(503, "Synthetic cache unavailable")
                    return
                super().do_GET()

            def log_message(handler, _format, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0),
            lambda *args, **kwargs: Handler(*args, directory=str(files), **kwargs),
        )
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True,
        )
        self.thread.start()
        self.origin = "http://127.0.0.1:%d/repo/" % self.server.server_port

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=10)


def checked(argv: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess:
    result = subprocess.run(
        argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=timeout, check=False,
    )
    if result.returncode:
        raise RuntimeError("Command failed (%s): %s\n%s" %
                           (result.returncode, argv[0], result.stdout[-4500:]))
    return result


def apt_repository(base: Path) -> Path:
    repository = base / "www" / "repo"
    index_dir = repository / "dists" / "stable" / "main" / "binary-amd64"
    index_dir.mkdir(parents=True)
    files = {
        "main/binary-amd64/Packages": b"",
        "main/binary-amd64/Packages.gz": gzip.compress(b"", mtime=0),
        "main/binary-amd64/Packages.xz": lzma.compress(b""),
    }
    for name, data in files.items():
        (repository / "dists" / "stable" / name).write_bytes(data)
    release = "\n".join([
        "Origin: REPOCACHE CI",
        "Label: REPOCACHE CI",
        "Suite: stable",
        "Codename: stable",
        "Date: %s" % email.utils.formatdate(usegmt=True),
        "Architectures: amd64",
        "Components: main",
        "SHA256:",
        *[" %s %s %s" % (hashlib.sha256(data).hexdigest(), len(data), name)
          for name, data in sorted(files.items())],
        "",
    ])
    meta = repository / "dists" / "stable"
    (meta / "Release").write_text(release, encoding="utf-8")

    homedir = base / "gnupg"
    homedir.mkdir(mode=0o700)
    gpg = ["gpg", "--homedir", str(homedir), "--batch", "--yes",
           "--pinentry-mode", "loopback", "--passphrase", ""]
    checked(gpg + ["--quick-generate-key",
                   "REPOCACHE Fixture <ci@repocache.invalid>",
                   "ed25519", "sign", "1d"])
    keyring = base / "fixture-keyring.gpg"
    keyring.write_bytes(checked(gpg + ["--export"]).stdout.encode("latin-1"))
    # gpg --export is binary: rewrite it with a byte-safe subprocess.
    with keyring.open("wb") as sink:
        subprocess.run(gpg + ["--export"], stdout=sink, check=True, timeout=20)
    keyring.chmod(0o644)
    checked(gpg + ["--clearsign", "--digest-algo", "SHA256",
                   "--output", str(meta / "InRelease"), str(meta / "Release")])
    return keyring


def dnf_repository(base: Path) -> None:
    repository = base / "www" / "repo"
    repository.mkdir(parents=True)
    checked(["createrepo_c", "--quiet", str(repository)])


def apt_command(base: Path, primary: HTTPBackend,
                upstream: HTTPBackend, cycle: str, keyring: Path) -> list[str]:
    mirrors = base / "mirrors.txt"
    mirrors.write_text(
        primary.origin + "\tpriority:1\n" +
        upstream.origin + "\tpriority:2\n",
        encoding="utf-8",
    )
    source = base / "ci.sources"
    source.write_text(
        "Types: deb\n"
        "URIs: mirror+file:%s\n" % mirrors +
        "Suites: stable\nComponents: main\n"
        "Signed-By: %s\n" % keyring,
        encoding="utf-8",
    )
    lists = base / ("apt-lists-" + cycle)
    (lists / "partial").mkdir(parents=True)
    cache = base / ("apt-cache-" + cycle)
    cache.mkdir()
    return [
        "apt-get", "update",
        "-o", "Dir::Etc::sourcelist=" + str(source),
        "-o", "Dir::Etc::sourceparts=-",
        "-o", "Dir::State::lists=" + str(lists),
        "-o", "Dir::Cache=" + str(cache),
        "-o", "APT::Update::Error-Mode=any",
        "-o", "Acquire::Retries=0",
        "-o", "APT::Sandbox::User=root",
    ]


def dnf_command(base: Path, primary: HTTPBackend,
                upstream: HTTPBackend, cycle: str) -> list[str]:
    repo_dir = base / "repos"
    repo_dir.mkdir(exist_ok=True)
    (repo_dir / "repocache-ci.repo").write_text(
        "[repocache-ci]\n"
        "name=REPOCACHE Native Metadata Probe\n"
        "enabled=1\n"
        "gpgcheck=1\n"
        "repo_gpgcheck=0\n"
        "skip_if_unavailable=0\n"
        "fastestmirror=0\n"
        "baseurl=%s\n        %s\n" % (primary.origin, upstream.origin),
        encoding="utf-8",
    )
    cache = base / ("dnf-cache-" + cycle)
    cache.mkdir()
    logs = base / ("dnf-logs-" + cycle)
    logs.mkdir()
    config = base / ("dnf-" + cycle + ".conf")
    config.write_text(
        "[main]\n"
        "reposdir=%s\n" % repo_dir +
        "cachedir=%s\n" % cache +
        "system_cachedir=%s\n" % cache +
        "logdir=%s\n" % logs +
        "skip_if_unavailable=0\n"
        "fastestmirror=0\n"
        "metadata_expire=0\n",
        encoding="utf-8",
    )
    executable = shutil.which("dnf5") or shutil.which("dnf")
    if not executable:
        raise RuntimeError("Missing DNF on native AlmaLinux container")
    return [executable, "--config=" + str(config), "--refresh", "makecache"]


def probe(manager: str) -> None:
    with tempfile.TemporaryDirectory(prefix="repocache-native-fallback-") as tmp:
        base = Path(tmp)
        (base / "www").mkdir()
        keyring = apt_repository(base) if manager == "apt" else None
        if manager == "dnf":
            dnf_repository(base)

        primary = HTTPBackend(base / "www")
        upstream = HTTPBackend(base / "www")
        try:
            command = apt_command if manager == "apt" else dnf_command
            cases = [
                ("preferred", "healthy", "healthy"),
                ("fallback", "unavailable", "healthy"),
                ("recovery", "healthy", "healthy"),
                ("both-failed", "unavailable", "unavailable"),
            ]
            for cycle, first, second in cases:
                primary.mode, upstream.mode = first, second
                primary.hits.clear()
                upstream.hits.clear()
                argv = (command(base, primary, upstream, cycle, keyring)
                        if manager == "apt"
                        else command(base, primary, upstream, cycle))
                result = subprocess.run(
                    argv, text=True, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, timeout=120, check=False,
                )
                print("%s %s exit=%d primary_hits=%d upstream_hits=%d" %
                      (manager, cycle, result.returncode,
                       len(primary.hits), len(upstream.hits)), flush=True)
                if cycle == "both-failed":
                    ok = result.returncode != 0 and primary.hits and upstream.hits
                elif cycle == "fallback":
                    ok = result.returncode == 0 and primary.hits and upstream.hits
                else:
                    ok = result.returncode == 0 and primary.hits and not upstream.hits
                if not ok:
                    raise RuntimeError(
                        "Failover assertion failed for %s / %s:\n%s" %
                        (manager, cycle, result.stdout[-6000:]))
        finally:
            primary.close()
            upstream.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("manager", choices=["apt", "dnf"])
    args = parser.parse_args()
    probe(args.manager)
