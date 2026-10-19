#!/usr/bin/env python3
"""Authenticated, fail-closed migration of the *published* v0.3.0 layout.

Run ONLY from an independently approved, signed v0.4.0 release checkout.
This root coordinator uses OS Python stdlib and OpenSSL only; it never imports,
installs or executes mutable release Python with root privileges. The signed
v0.4 source is executed solely after dropping to the repocache service UID.
"""
from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from pathlib import Path

LEGACY_ROOT = Path("/opt/repocache-cli")
MANAGED = LEGACY_ROOT / "managed"
OLD_MANIFEST = LEGACY_ROOT / "installed.json"
OLD_CURRENT = LEGACY_ROOT / "current"
LINKS = (Path("/usr/local/bin/repocache"), Path("/usr/bin/repocache"))
HELPER = Path("/usr/local/libexec/repocache-recover.py")
JOURNAL = LEGACY_ROOT / ".migration-v030.json"
SAVED = LEGACY_ROOT / ".migration-v030.saved.json"
OLD_ARCHIVE_SHA256 = "9719e82b71fe7763e7c8570eaa54b0282217e2086baf83fa50ebdf58ef3f3283"
OLD_COMMIT = "d56e74785eeb0fe778b4b81a265d237dc261622a"
VERSION = "0.4.0"
MAX_ARCHIVE = 12_000_000
EXPECTED_PY = {("debian", "13"): (3, 13), ("almalinux", "10"): (3, 12)}


class MigrationError(RuntimeError):
    """Fail before altering the active historical REPOCACHE installation."""


def fail(condition: bool, reason: str) -> None:
    if not condition:
        raise MigrationError(reason)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checked_file(path: Path, limit: int) -> bytes:
    fail(not path.is_symlink() and path.is_file()
         and stat.S_ISREG(path.lstat().st_mode)
         and path.stat().st_size <= limit and path.stat().st_nlink == 1,
         "Missing, unsafe or oversized authenticated input: " + path.name)
    return path.read_bytes()


def sync(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def durable(path: Path, data: bytes, mode: int = 0o600) -> None:
    fail(not path.is_symlink(), "Refusing symlinked migration state")
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".migration-tmp-")
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
        sync(path.parent)
    finally:
        if os.path.lexists(name):
            os.unlink(name)


def remove(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
        sync(path.parent)


def proc(*argv: str, timeout: int = 120, input: bytes | None = None) -> bytes:
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C",
           "HOME": "/root", "PYTHONNOUSERSITE": "1",
           "PYTHONSAFEPATH": "1", "PIP_CONFIG_FILE": os.devnull}
    try:
        result = subprocess.run(list(map(str, argv)), env=env, input=input,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise MigrationError("Trusted OS operation failed") from exc
    fail(result.returncode == 0, "Trusted OS operation returned failure: " + str(argv[0]))
    return result.stdout


def strict_json(raw: bytes) -> dict:
    def unique(pairs):
        data = {}
        for key, value in pairs:
            if key in data:
                raise MigrationError("Duplicate identity field")
            data[key] = value
        return data
    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (TypeError, UnicodeError, ValueError) as exc:
        raise MigrationError("Invalid authenticated metadata") from exc
    fail(type(value) is dict, "Expected metadata object")
    return value


def policy_runtime() -> None:
    fail(os.geteuid() == 0 and Path(sys.executable).resolve()
         == Path("/usr/bin/python3").resolve(),
         "Run as root using OS-owned /usr/bin/python3 -I")
    values = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            if k in ("ID", "VERSION_ID"):
                fail(k not in values, "Duplicate OS identity")
                values[k] = v.strip('"').strip("'")
    pair = (values.get("ID"), values.get("VERSION_ID", "").split(".")[0])
    fail(EXPECTED_PY.get(pair) == sys.version_info[:2],
         "Only Debian 13/Python 3.13 and AlmaLinux 10/Python 3.12 are supported")


def tar_parts(data: bytes, version: str) -> dict[str, bytes]:
    from io import BytesIO
    files = {}
    try:
        with tarfile.open(fileobj=BytesIO(data), mode="r:gz") as archive:
            for item in archive:
                prefix = "repocache-v" + version + "/"
                fail(item.isfile() and item.name.startswith(prefix),
                     "Unexpected release archive member type/path")
                name = item.name[len(prefix):]
                path = Path(name)
                fail(len(files) < 90 and name and not path.is_absolute()
                     and ".." not in path.parts and str(path) == name
                     and name not in files and item.size <= 2_000_000,
                     "Unsafe or duplicate release file")
                reader = archive.extractfile(item)
                fail(reader is not None, "Unreadable signed archive member")
                files[name] = reader.read(item.size + 1)
                fail(len(files[name]) == item.size, "Archive member size mismatch")
    except (OSError, tarfile.TarError, EOFError) as exc:
        raise MigrationError("Invalid release archive") from exc
    return files


def legacy_identity(archive: Path) -> dict:
    contents = checked_file(archive, MAX_ARCHIVE)
    fail(digest(contents) == OLD_ARCHIVE_SHA256, "Not the authentic pinned published v0.3.0")
    files = tar_parts(contents, "0.3.0")
    required = ["pyproject.toml", "install.sh"] + sorted(
        p for p in files if p.startswith("src/repocache/") and p.endswith(".py"))
    fail(len(required) >= 6, "Unexpected historical release package")
    h = hashlib.sha256()
    for name in required:
        fail(name in files, "Historical release source is incomplete")
        h.update(name.encode() + b"\0" + files[name] + b"\0")
    old_digest = h.hexdigest()
    fail(LEGACY_ROOT.is_dir() and not LEGACY_ROOT.is_symlink()
         and LEGACY_ROOT.stat().st_uid == 0,
         "Unrecognized root-owned historical installation root")
    old = strict_json(checked_file(OLD_MANIFEST, 32768))
    fail(old.get("version") == "0.3.0" and old.get("source_digest") == old_digest,
         "Existing installation differs from the authenticated published v0.3.0")
    old_target = str(LEGACY_ROOT / "releases" / ("0.3.0-" + old_digest[:12]))
    fail(OLD_CURRENT.is_symlink() and os.readlink(OLD_CURRENT) == old_target
         and Path(old_target, "bin/repocache").is_file(),
         "Historical active generation is not the expected published version")
    expected = old_target + "/bin/repocache"
    snapshots = {}
    for link in LINKS:
        fail(not link.exists() or link.is_symlink(),
             "A foreign launcher occupies a REPOCACHE command path")
        target = os.readlink(link) if link.is_symlink() else None
        fail(target is None or target in (str(OLD_CURRENT / "bin/repocache"), expected),
             "Unknown historical launcher: " + str(link))
        snapshots[str(link)] = target
    fail(any(t is not None for t in snapshots.values()),
         "Missing published v0.3.0 launcher")
    return {"archive_sha256": OLD_ARCHIVE_SHA256,
            "manifest_sha256": digest(OLD_MANIFEST.read_bytes()),
            "legacy_target": old_target, "links": snapshots}


def trusted_anchor(key_id: str) -> Path:
    fail(re.fullmatch(r"[a-z][a-z0-9-]{0,47}", key_id) is not None,
         "Invalid trust key identifier")
    key = Path("/etc/repocache/trust.d") / (key_id + ".pem")
    for path in [Path("/etc"), Path("/etc/repocache"),
                 Path("/etc/repocache/trust.d"), key]:
        fail(not path.is_symlink() and path.exists()
             and path.stat().st_uid == 0 and not path.stat().st_mode & 0o022,
             "Unsafe owner-managed trust anchor")
    checked_file(key, 16384)
    return key


def authenticated_candidate(args) -> dict[str, bytes]:
    key = trusted_anchor(args.key_id)
    release = checked_file(args.bundle, MAX_ARCHIVE)
    sha_line = checked_file(args.checksum, 256).decode("ascii")
    fail(sha_line == digest(release) + "  " + args.bundle.name + "\n",
         "Incorrect release transport checksum")
    raw = checked_file(args.manifest, 16384)
    sig = checked_file(args.signature, 64)
    fail(len(sig) == 64, "Invalid detached signature")
    proc("/usr/bin/openssl", "pkeyutl", "-verify", "-pubin", "-inkey",
         str(key), "-rawin", "-in", str(args.manifest),
         "-sigfile", str(args.signature), timeout=15)
    metadata = strict_json(raw)
    fail(metadata.get("schema") == 1
         and metadata.get("key_id") == args.key_id
         and metadata.get("repository") == "teixemf/repocache"
         and metadata.get("version") == VERSION
         and metadata.get("archive") == args.bundle.name
         and metadata.get("archive_sha256") == digest(release)
         and isinstance(metadata.get("commit"), str)
         and re.fullmatch(r"[a-f0-9]{40}", metadata["commit"])
         and isinstance(metadata.get("issued_at"), int)
         and isinstance(metadata.get("expires_at"), int)
         and metadata["issued_at"] <= int(time.time()) < metadata["expires_at"],
         "Unsigned, expired or mismatched release identity")
    wheels = checked_file(args.wheelhouse, 75_000_000)
    fail(metadata.get("wheelhouse_sha256") == digest(wheels),
         "Offline wheelhouse does not match signed manifest")
    files = tar_parts(release, VERSION)
    policy = strict_json(files.get("release-policy.json", b""))
    fail(metadata.get("policy_sha256") == digest(files["release-policy.json"])
         and policy.get("schema") == 1 and policy.get("version") == VERSION
         and "0.3.0" in policy.get("compatible_from", [])
         and ("debian", "13") in {(t.get("id"), t.get("major")) for t in policy.get("targets", [])}
         and ("almalinux", "10") in {(t.get("id"), t.get("major")) for t in policy.get("targets", [])},
         "Incompatible signed migration policy")
    return files


def trust_scripts(files: dict[str, bytes], launcher_sha: str, recovery_sha: str) -> None:
    for name, expected in (("scripts/repocache-launcher.sh", launcher_sha),
                           ("src/repocache/recovery.py", recovery_sha)):
        fail(re.fullmatch(r"[a-f0-9]{64}", expected) is not None
             and name in files and digest(files[name]) == expected,
             "Root-owned launcher/recovery fingerprints were not independently approved")


def source_tree(files: dict[str, bytes]) -> Path:
    path = LEGACY_ROOT / (".verified-migration-" + uuid.uuid4().hex)
    path.mkdir(mode=0o755)
    try:
        for name, data in files.items():
            target = path / name
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            target.write_bytes(data)
            target.chmod(0o644)
        sync(path)
    except BaseException:
        shutil.rmtree(path)
        raise
    return path


def prepare_lock(group_id: int) -> None:
    """Prepare the same trusted inode that signed v0.4 recovery/updater uses.

    Old v0.3 installations do not have this file. Do not replace an existing
    lock while another migration or updater could hold it.
    """
    for ancestor in (Path("/"), Path("/opt")):
        info = ancestor.lstat()
        fail(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
             and not stat.S_IMODE(info.st_mode) & 0o022,
             "Unsafe privileged migration ancestor")
    directory = LEGACY_ROOT.lstat()
    fail(stat.S_ISDIR(directory.st_mode) and directory.st_uid == 0
         and not stat.S_IMODE(directory.st_mode) & 0o022,
         "Legacy root directory is unsafe for permanent update locking")
    parent_fd = os.open(LEGACY_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            fd = os.open(".updater.lock",
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o400, dir_fd=parent_fd)
        except FileExistsError:
            pass
        else:
            try:
                os.fchown(fd, 0, group_id)
                os.fchmod(fd, 0o440)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(parent_fd)
        fd = os.open(".updater.lock", os.O_RDONLY | os.O_NOFOLLOW,
                     dir_fd=parent_fd)
        try:
            meta = os.fstat(fd)
            fail(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0
                 and meta.st_gid == group_id and meta.st_nlink == 1
                 and stat.S_IMODE(meta.st_mode) == 0o440,
                 "Unsafe persistent updater lock")
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def prepare_uid() -> int:
    try:
        account = pwd.getpwnam("repocache")
    except KeyError:
        proc("/usr/sbin/useradd", "--system", "--user-group", "--home-dir",
             "/var/lib/repocache", "--shell", "/usr/sbin/nologin",
             "--no-create-home", "repocache")
        account = pwd.getpwnam("repocache")
    fail(account.pw_uid > 0, "Invalid managed service identity")
    for directory in (MANAGED, Path("/var/lib/repocache")):
        if directory.exists():
            fail(directory.is_dir() and not directory.is_symlink()
                 and directory.stat().st_uid == account.pw_uid,
                 "Foreign rootless state, migration refused")
        else:
            directory.mkdir(mode=0o700)
            os.chown(directory, account.pw_uid, account.pw_gid)
        directory.chmod(0o700)
    prepare_lock(account.pw_gid)
    return account.pw_uid


def stage_verified_upgrade(args, source: Path) -> None:
    # Authenticated release code executes ONLY under the service identity.
    # The root coordinator has already independently verified the old links.
    # The narrow in-memory override prevents *staging* from rejecting the
    # still-working historical launchers; it cannot modify these root links.
    code = (
        "import sys; from pathlib import Path; "
        "sys.path.insert(0, sys.argv[1]); "
        "from repocache import updater, upgrade; "
        "updater._safe_links = lambda: None; "
        "upgrade.upgrade(selected='0.4.0', bundle=Path(sys.argv[2]), "
        "checksum=Path(sys.argv[3]), manifest=Path(sys.argv[4]), "
        "signature=Path(sys.argv[5]), wheels=Path(sys.argv[6]))"
    )
    env = ["/usr/sbin/runuser", "-u", "repocache", "--",
           "/usr/bin/env", "-i", "PATH=/usr/bin:/bin",
           "HOME=/var/lib/repocache", "LANG=C.UTF-8", "PYTHONNOUSERSITE=1",
           "PYTHONSAFEPATH=1", "/usr/bin/python3", "-I", "-c", code,
           str(source / "src"), str(args.bundle), str(args.checksum),
           str(args.manifest), str(args.signature), str(args.wheelhouse)]
    proc(*env, timeout=480)
    proc("/usr/sbin/runuser", "-u", "repocache", "--",
         str(MANAGED / "current/bin/repocache"), "--version", timeout=20)
    installed = strict_json(checked_file(MANAGED / "installed.json", 32768))
    fail(installed.get("version") == VERSION and (MANAGED / "current").is_symlink(),
         "New rootless candidate did not finish authenticated activation")


def link_snapshot() -> dict[str, str | None]:
    return {str(path): os.readlink(path) if path.is_symlink() else None for path in LINKS}


def restore_link(path: Path, previous: str | None,
                 approved_launcher_sha: str) -> None:
    # /usr/local/bin/repocache becomes a root-owned REGULAR file during
    # migration; do not refuse to recover merely because the process died
    # after that atomic replacement. Still reject any foreign replacement.
    if path.exists() and not path.is_symlink():
        fail(path == LINKS[0] and path.is_file()
             and path.stat().st_uid == os.geteuid()
             and digest(checked_file(path, 65536)) == approved_launcher_sha,
             "Foreign file replaced a migration-owned launcher")
    if previous is None:
        remove(path)
        return
    tmp = path.parent / (".repocache-link-" + uuid.uuid4().hex)
    tmp.symlink_to(previous)
    os.replace(tmp, path)
    sync(path.parent)


def install_launcher(path: Path, data: bytes) -> None:
    # The original v0.3.0 launcher is a previously verified *symlink*.
    # os.replace of a temporary root-owned regular file is safe: it never
    # writes through the legacy symlink or touches the old active venv.
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".rootless-next-")
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(name, 0o755)
        os.replace(name, path)
        sync(path.parent)
    finally:
        if os.path.lexists(name):
            os.unlink(name)


def save_record(path: Path, old: dict, launcher_digest: str) -> None:
    data = {"schema": 1, "legacy": old, "launcher_sha256": launcher_digest}
    durable(path, (json.dumps(data, sort_keys=True) + "\n").encode())


def load_record(path: Path) -> dict:
    data = strict_json(checked_file(path, 32768))
    fail(data.get("schema") == 1 and isinstance(data.get("legacy"), dict)
         and set(data["legacy"].get("links", {})) == {str(p) for p in LINKS},
         "Corrupt migration checkpoint")
    old = data["legacy"]
    fail(old.get("archive_sha256") == OLD_ARCHIVE_SHA256
         and old.get("manifest_sha256") == digest(checked_file(OLD_MANIFEST, 32768))
         and (OLD_CURRENT.is_symlink()
              and os.readlink(OLD_CURRENT) == old.get("legacy_target")),
         "Historical rollback checkpoint no longer matches immutable baseline")
    for value in old["links"].values():
        fail(value is None or value in
             (str(OLD_CURRENT / "bin/repocache"),
              str(old["legacy_target"]) + "/bin/repocache"),
             "Untrusted historical launcher checkpoint")
    return data


def recover() -> bool:
    if not JOURNAL.exists() and not JOURNAL.is_symlink():
        return False
    record = load_record(JOURNAL)
    old = record["legacy"]
    for link in LINKS:
        restore_link(link, old["links"][str(link)],
                     record["launcher_sha256"])
    remove(JOURNAL)
    remove(SAVED)  # committed status is invalid if recovery rolled back
    return True


def cutover(files: dict[str, bytes], old: dict, launcher_sha: str) -> None:
    HELPER.parent.mkdir(parents=True, exist_ok=True)
    fail(HELPER.parent.is_dir() and HELPER.parent.stat().st_uid == os.geteuid()
         and not HELPER.parent.is_symlink(),
         "Trusted recovery helper directory is unavailable")
    if HELPER.exists() or HELPER.is_symlink():
        fail(digest(checked_file(HELPER, 65536))
             == digest(files["src/repocache/recovery.py"])
             and HELPER.stat().st_uid == os.geteuid(),
             "Foreign recovery helper cannot be overwritten")
    fail(not LINKS[0].exists() or LINKS[0].is_symlink(),
         "Foreign root-owned launcher cannot be overwritten")
    save_record(JOURNAL, old, launcher_sha)
    durable(HELPER, files["src/repocache/recovery.py"], mode=0o644)
    install_launcher(LINKS[0], files["scripts/repocache-launcher.sh"])
    restore_link(LINKS[1], str(LINKS[0]), launcher_sha)
    fail(digest(checked_file(LINKS[0], 65536)) == launcher_sha,
         "Installed root-owned launcher differs from authenticated candidate")
    save_record(SAVED, old, launcher_sha)
    remove(JOURNAL)


def rollback() -> None:
    fail(SAVED.exists() and not SAVED.is_symlink(), "No authenticated migrated state to roll back")
    previous = load_record(SAVED)["legacy"]
    launcher_sha = strict_json(SAVED.read_bytes())["launcher_sha256"]
    fail(digest(checked_file(LINKS[0], 65536)) == launcher_sha
         and os.readlink(LINKS[1]) == str(LINKS[0]),
         "Unexpected active launcher; refusing unsafe rollback")
    save_record(JOURNAL, previous, launcher_sha)
    for link in LINKS:
        restore_link(link, previous["links"][str(link)], launcher_sha)
    remove(JOURNAL)
    remove(SAVED)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--legacy-archive", type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--checksum", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--signature", type=Path)
    parser.add_argument("--wheelhouse", type=Path)
    parser.add_argument("--key-id", default="repocache-2026-10")
    parser.add_argument("--launcher-sha256", default="")
    parser.add_argument("--recovery-sha256", default="")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--recover", action="store_true")
    modes.add_argument("--rollback", action="store_true")
    args = parser.parse_args()
    policy_runtime()
    fail(not LEGACY_ROOT.is_symlink() and LEGACY_ROOT.is_dir()
         and LEGACY_ROOT.stat().st_uid == 0, "Legacy installation absent")
    fd = os.open(LEGACY_ROOT / ".migration.lock",
                 os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fail(os.fstat(fd).st_uid == 0 and not os.fstat(fd).st_mode & 0o077,
             "Unsafe privileged migration lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise MigrationError("Another legacy migration is running") from exc
        if args.recover:
            print("RECOVERED" if recover() else "NO_PENDING_MIGRATION")
            return
        if JOURNAL.exists() or JOURNAL.is_symlink():
            recover()
            raise MigrationError("Interrupted migration restored; rerun after review")
        if args.rollback:
            rollback()
            print("PASS: verified legacy launchers restored; managed generation preserved")
            return
        fail(not SAVED.exists() and not SAVED.is_symlink(),
             "Already migrated; use explicit --rollback after review")
        for name in ("legacy_archive", "bundle", "checksum", "manifest",
                     "signature", "wheelhouse"):
            fail(getattr(args, name) is not None, "Missing required authenticated artifact: " + name)
        # Validate ALL authenticated inputs and both old and new trust boundaries
        # BEFORE creating accounts, files or changing any launcher.
        old = legacy_identity(args.legacy_archive)
        files = authenticated_candidate(args)
        trust_scripts(files, args.launcher_sha256, args.recovery_sha256)
        prepare_uid()
        source = source_tree(files)
        try:
            stage_verified_upgrade(args, source)
            cutover(files, old, args.launcher_sha256)
        except BaseException:
            if JOURNAL.exists():
                recover()
            raise
        finally:
            shutil.rmtree(source)
        print("PASS: real published v0.3.0 migrated to authenticated rootless 0.4.0")
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        main()
    except (MigrationError, OSError, ValueError, KeyError, TypeError) as exc:
        print("REFUSED: " + str(exc), file=sys.stderr)
        sys.exit(2)
