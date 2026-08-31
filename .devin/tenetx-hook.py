#!/usr/bin/env python3
"""TenetX hook for Devin Cloud and Devin Outposts.

Cognition's Cloud VM has no ~/.windsurf/hooks install. This file is committed
to the repo as `.devin/tenetx-hook.py` (or pasted as a team hook command) and
runs on the machine that actually executes tools. It downloads the Windsurf
guard from the control plane, verifies it, then execs it with the same stdin.

Required Devin secrets / environment:
  TENETX_URL          control-plane origin (https://<org>.tenetx.ai)
  TENETX_ORG          org slug
  TENETX_VMCP_TOKEN   Windsurf VMCP token (same hook_type as Devin Local)

Missing credentials fail open so Cloud sessions are not bricked. Every
fail-open path writes a breadcrumb to ~/.tenetx/capture_failures.jsonl, so an
unguarded Cloud session stays observable to `tenetx doctor`.

Keep byte-identical with cli-go/internal/hooks/devin_cloud_hook.py and
.devin/tenetx-hook.py; tests/vmcp/test_devin_cloud.py enforces that.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

HOOK_TYPE = "windsurf"
USER_AGENT = "TenetX-VMCP/1.0"
GUARD_TTL_SECONDS = 3600
# The hooks.v1.json entry declares timeout=10, so the download and the guard
# exec together must stay under it or Devin kills the hook mid-guard.
DOWNLOAD_TIMEOUT_SECONDS = 3
GUARD_TIMEOUT_SECONDS = 5
BREADCRUMB_MAX_LINES = 200
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def _env(name: str) -> str:
    return str(os.environ.get(name) or "").strip()


def _home() -> str:
    home = os.path.expanduser("~")
    return "" if not home or home == "~" else home


def _breadcrumb(reason: str, **fields: object) -> None:
    """Append one bounded JSONL breadcrumb. Best-effort; never raises."""
    try:
        path = _env("TENETX_CAPTURE_FAILURES_PATH")
        if not path:
            home = _home()
            if not home:
                return
            path = os.path.join(home, ".tenetx", "capture_failures.jsonl")
        event = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "hook": f"{HOOK_TYPE}-devin-cloud",
            "reason": reason,
        }
        for key, value in fields.items():
            event[key] = str(value)[:300]
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, mode=0o700, exist_ok=True)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(event) + "\n")
        with open(path, encoding="utf-8") as handle:
            lines = handle.readlines()
        if len(lines) > BREADCRUMB_MAX_LINES:
            with open(path, "w", encoding="utf-8") as handle:
                handle.writelines(lines[-BREADCRUMB_MAX_LINES:])
    except Exception:
        pass


def _fail_open(reason: str, **fields: object) -> int:
    _breadcrumb(reason, **fields)
    detail = fields.get("detail") or reason
    sys.stderr.write(f"[tenetx] Devin Cloud hook skipped: {detail}\n")
    return 0


def _token() -> str:
    token = _env("TENETX_VMCP_TOKEN")
    if token:
        return token
    path = _env("TENETX_VMCP_TOKEN_FILE")
    if not path:
        return ""
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError as exc:
        _breadcrumb("token_file_unreadable", path=path, error=type(exc).__name__)
        return ""


def _is_insecure_url(url: str) -> bool:
    """Plaintext control-plane URLs leak the VMCP token and the guard bytes."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme == "https":
        return False
    if parsed.scheme == "http":
        return (parsed.hostname or "").lower() not in LOOPBACK_HOSTS
    return True


def _guard_path() -> str:
    override = _env("TENETX_DEVIN_CLOUD_GUARD")
    if override:
        return override
    home = _home()
    if home:
        return os.path.join(home, ".tenetx", "cache", f"tenetx-{HOOK_TYPE}-guard.py")
    uid = getattr(os, "geteuid", lambda: "nouid")()
    return os.path.join(
        tempfile.gettempdir(), f"tenetx-{uid}", f"tenetx-{HOOK_TYPE}-guard.py"
    )


def _owned_by_this_user(info: os.stat_result) -> bool:
    geteuid = getattr(os, "geteuid", None)
    return geteuid is None or info.st_uid == geteuid()


def _dir_trusted(directory: str) -> bool:
    """Nobody but this user (or root) may swap the guard between check and exec."""
    try:
        info = os.stat(directory)
    except OSError:
        return False
    if not _owned_by_this_user(info) and info.st_uid != 0:
        return False
    return not bool(info.st_mode & (stat.S_IWGRP | stat.S_IWOTH))


def _guard_trusted(path: str) -> bool:
    """Only exec a cached guard this user owns and nobody else can rewrite.

    A fixed world-writable cache path (the old /tmp default) let any local
    user pre-create the file and have it executed as the agent user.
    """
    directory = os.path.dirname(path) or "."
    if not _dir_trusted(directory):
        _breadcrumb("guard_cache_dir_untrusted", path=directory)
        return False
    try:
        info = os.lstat(path)
    except OSError:
        return False
    if not stat.S_ISREG(info.st_mode):
        _breadcrumb("guard_cache_not_regular_file", path=path)
        return False
    if not _owned_by_this_user(info):
        _breadcrumb("guard_cache_foreign_owner", path=path, uid=info.st_uid)
        return False
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        _breadcrumb(
            "guard_cache_group_or_world_writable",
            path=path,
            mode=oct(info.st_mode & 0o777),
        )
        return False
    return info.st_size > 0


def _guard_fresh(path: str) -> bool:
    try:
        age = time.time() - os.stat(path).st_mtime
    except OSError:
        return False
    return 0 <= age < GUARD_TTL_SECONDS


def _looks_like_guard(body: bytes) -> bool:
    return body.strip().startswith(b"#!") or b"def main(" in body


def _write_guard(body: bytes, dest: str) -> str | None:
    directory = os.path.dirname(dest) or "."
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    except OSError as exc:
        _breadcrumb(
            "guard_cache_dir_unwritable", path=directory, error=type(exc).__name__
        )
        return None
    if not _dir_trusted(directory):
        _breadcrumb("guard_cache_dir_untrusted", path=directory)
        return None
    try:
        fd, tmp = tempfile.mkstemp(prefix="tenetx-guard.", dir=directory)
    except OSError as exc:
        _breadcrumb("guard_tempfile_failed", path=directory, error=type(exc).__name__)
        return None
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(body)
        # Run as `sys.executable <guard>`, so no execute bit is needed.
        os.chmod(tmp, 0o600)
        os.replace(tmp, dest)
    except OSError as exc:
        _breadcrumb("guard_write_failed", path=dest, error=type(exc).__name__)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return None
    return dest


def _download_guard(url: str, org: str, token: str, dest: str) -> str | None:
    endpoint = f"{url.rstrip('/')}/api/vmcp/{org}/{HOOK_TYPE}/script"
    request = urllib.request.Request(
        endpoint,
        headers={
            "Authorization": f"Bearer {token}",
            "User-Agent": USER_AGENT,
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(
            request, timeout=DOWNLOAD_TIMEOUT_SECONDS
        ) as response:
            body = response.read()
            expected = (response.headers.get("X-TenetX-SHA256") or "").strip().lower()
            version = (response.headers.get("X-TenetX-Version") or "").strip()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        _breadcrumb(
            "guard_download_failed",
            endpoint=endpoint,
            status=getattr(exc, "code", "exception"),
            error=f"{type(exc).__name__}: {exc}",
        )
        return None
    if not _looks_like_guard(body):
        _breadcrumb("guard_download_not_python", endpoint=endpoint, bytes=len(body))
        return None
    if expected:
        actual = hashlib.sha256(body).hexdigest()
        if actual != expected:
            _breadcrumb(
                "guard_sha256_mismatch",
                endpoint=endpoint,
                expected=expected,
                actual=actual,
                version=version,
            )
            return None
    else:
        # The control plane should always advertise the digest; executing an
        # unverified artifact is a downgrade worth seeing in `tenetx doctor`.
        _breadcrumb("guard_sha256_header_missing", endpoint=endpoint, version=version)
    return _write_guard(body, dest)


def main() -> int:
    url = _env("TENETX_URL")
    org = _env("TENETX_ORG")
    token = _token()
    if not url or not org or not token:
        return _fail_open(
            "missing_credentials",
            detail="set TENETX_URL, TENETX_ORG, and TENETX_VMCP_TOKEN as Devin secrets",
        )
    if _is_insecure_url(url):
        return _fail_open(
            "insecure_control_plane_url",
            url=url,
            detail=f"TENETX_URL must use https (got {url})",
        )
    os.environ["TENETX_URL"] = url
    os.environ["TENETX_ORG"] = org
    os.environ["TENETX_VMCP_TOKEN"] = token
    os.environ.setdefault("TENETX_FAIL_MODE", "open")
    os.environ.setdefault("TENETX_INSTALL_MODE", "unmanaged")
    payload = sys.stdin.buffer.read()
    guard = _guard_path()
    cached = _guard_trusted(guard)
    if not (cached and _guard_fresh(guard)):
        if _download_guard(url, org, token, guard) is None:
            if not cached:
                return _fail_open(
                    "guard_unavailable",
                    path=guard,
                    detail="could not download the Windsurf guard from the control plane",
                )
            # A stale-but-trusted guard still enforces policy, so running it
            # beats failing open — but the staleness must not be silent.
            _breadcrumb("guard_refresh_failed_using_cached_guard", path=guard)
    try:
        result = subprocess.run(
            [sys.executable, guard],
            input=payload,
            timeout=GUARD_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _fail_open(
            "guard_exec_failed",
            path=guard,
            error=type(exc).__name__,
            detail="guard exec failed",
        )
    return int(result.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
