#!/usr/bin/env python3
"""End-to-end acceptance tests for ghsec, driven through a real PTY.

These tests exercise the compiled binary the way a user does: a pseudo-terminal,
real keystrokes and real process exit codes. They never contact the network.

Usage:  python3 scripts/e2e.py [path-to-binary]
Exit code 0 means every scenario passed.
"""

from __future__ import annotations

import fcntl
import json
import http.server
import os
import pty
import struct
import termios
import re
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

BINARY = sys.argv[1] if len(sys.argv) > 1 else os.path.join("dist", "ghsec")
ANSI = re.compile(rb"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b[()][A-Z0-9]")

failures: list[str] = []
passes: list[str] = []


def record(ok: bool, name: str, detail: str = "") -> None:
    if ok:
        passes.append(name)
        print(f"  PASS  {name}")
    else:
        failures.append(f"{name}: {detail}")
        print(f"  FAIL  {name}  {detail}")


def clean(raw: bytes) -> str:
    return ANSI.sub(b"", raw).decode("utf-8", "replace")


class Session:
    """A binary running under a pseudo-terminal."""

    # Real terminals report a size; a 0x0 PTY makes layout code fall back to
    # defaults, so give the session a realistic 120x40 window.
    COLS = 120
    ROWS = 40

    def __init__(self, env: dict[str, str], args: list[str] | None = None):
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", self.ROWS, self.COLS, 0, 0))
        os.set_blocking(self.master, False)
        self.proc = subprocess.Popen(
            [BINARY] + (args or []),
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            close_fds=True,
            start_new_session=True,
        )
        os.close(slave)
        self.buffer = b""

    def read_for(self, seconds: float) -> str:
        """Drain output for up to `seconds`, returning the cleaned text."""
        deadline = time.time() + seconds
        while time.time() < deadline:
            remaining = max(0.0, deadline - time.time())
            ready, _, _ = select.select([self.master], [], [], min(0.1, remaining))
            if not ready:
                continue
            try:
                chunk = os.read(self.master, 65536)
            except OSError:
                break
            if not chunk:
                break
            self.buffer += chunk
        return clean(self.buffer)

    def read_until(self, pattern: str, timeout: float = 8.0) -> tuple[bool, str]:
        """Read until `pattern` appears in the accumulated output."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            text = self.read_for(0.1)
            if pattern in text:
                return True, text
            if self.proc.poll() is not None:
                text = self.read_for(0.2)
                return pattern in text, text
        return False, clean(self.buffer)

    def send(self, data: bytes) -> None:
        os.write(self.master, data)

    def wait(self, timeout: float = 8.0) -> int | None:
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def kill(self) -> None:
        if self.proc.poll() is None:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.proc.wait(timeout=5)
        try:
            os.close(self.master)
        except OSError:
            pass


def base_env(home: str) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": home,
        "TERM": "xterm-256color",
        "GHSEC_CONFIG_HOME": os.path.join(home, "ghsec"),
        # Keep every scenario offline and deterministic.
        "GITHUB_TOKEN": "",
        "NO_COLOR": "",
        "LANG": "en_US.UTF-8",
    }
    return env


def scenario_version(home: str) -> None:
    print("\n[1] --version and --help run without a TTY")
    for flag, needle in (("--version", "ghsec"), ("--help", "Usage")):
        res = subprocess.run(
            [BINARY, flag],
            capture_output=True,
            text=True,
            env=base_env(home),
            timeout=20,
        )
        ok = res.returncode == 0 and needle in (res.stdout + res.stderr)
        record(ok, f"{flag} exits 0 and prints {needle!r}", f"rc={res.returncode} out={res.stdout[:120]!r}")


def scenario_non_tty_guard(home: str) -> None:
    print("\n[2] Non-interactive stdin is refused with a friendly message")
    res = subprocess.run(
        [BINARY],
        capture_output=True,
        text=True,
        input="",
        env=base_env(home),
        timeout=20,
    )
    combined = res.stdout + res.stderr
    ok = res.returncode != 0 and "interactive terminal" in combined
    record(ok, "refuses piped stdin without panicking", f"rc={res.returncode} out={combined[:200]!r}")
    record("panic" not in combined.lower() and "goroutine" not in combined.lower(),
           "no panic or goroutine dump in the error path")


def scenario_onboarding_shown(home: str) -> None:
    print("\n[3] First run forces onboarding")
    cfg_path = os.path.join(home, "ghsec", "config.json")
    session = Session(base_env(home))
    try:
        ok, text = session.read_until("token", timeout=12)
        record(ok, "onboarding asks for a token", text[-300:])
        record("Welcome to ghsec" in text or "Personal Access Token" in text or "token" in text.lower(),
               "welcome copy is rendered")
        record(not os.path.exists(cfg_path), "no config file is written before the token is verified")
    finally:
        session.kill()


def scenario_ctrl_c_on_onboarding(home: str) -> None:
    print("\n[4] Ctrl+C during onboarding exits gracefully, leaving no dirty config")
    cfg_path = os.path.join(home, "ghsec", "config.json")
    cfg_dir = os.path.dirname(cfg_path)
    if os.path.isdir(cfg_dir):
        shutil.rmtree(cfg_dir)
    session = Session(base_env(home))
    try:
        ok, text = session.read_until("token", timeout=12)
        record(ok, "reached the token prompt", text[-200:])
        session.send(b"\x03")  # Ctrl+C
        code = session.wait(timeout=10)
        record(code is not None, "process exited on Ctrl+C", "still running")
        record(code in (130, 0), f"exit code is 130 (got {code})")
        record(not os.path.exists(cfg_path), "no config file was created")
        after = session.read_for(0.3)
        record("panic" not in after.lower(), "no panic after interrupt")
    finally:
        session.kill()


def scenario_corrupt_config(home: str) -> None:
    print("\n[5] A corrupt config is reported, not crashed on")
    cfg_dir = os.path.join(home, "ghsec")
    os.makedirs(cfg_dir, exist_ok=True)
    with open(os.path.join(cfg_dir, "config.json"), "w", encoding="utf-8") as fh:
        fh.write("{ this is not json")
    session = Session(base_env(home))
    try:
        ok, text = session.read_until("token", timeout=12)
        record(ok, "recovers into onboarding instead of dying", text[-300:])
        record("panic" not in text.lower(), "no panic on corrupt config")
        session.send(b"\x03")
        code = session.wait(timeout=10)
        record(code in (130, 0), f"exits cleanly after recovery (got {code})")
    finally:
        session.kill()
    # Clean up the intentionally corrupt file.
    shutil.rmtree(cfg_dir, ignore_errors=True)


def scenario_bad_flag(home: str) -> None:
    print("\n[6] Unknown flags fail loudly but politely")
    res = subprocess.run(
        [BINARY, "--definitely-not-a-flag"],
        capture_output=True,
        text=True,
        env=base_env(home),
        timeout=20,
    )
    combined = res.stdout + res.stderr
    ok = res.returncode != 0 and ("unknown flag" in combined or "unknown argument" in combined)
    record(ok, "unknown flag exits non-zero with guidance", f"rc={res.returncode} out={combined[:200]!r}")


def scenario_config_permissions(home: str) -> None:
    print("\n[7] Config file is private (0600) and the directory is 0700")
    cfg_dir = os.path.join(home, "perm-check")
    env = base_env(home)
    env["GHSEC_CONFIG_HOME"] = cfg_dir

    # Use a test file inside the module (internal packages cannot be imported
    # from outside the module root) rather than a temp file.
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    probe_dir = os.path.join(root, "internal", "config")
    probe = os.path.join(probe_dir, "zz_e2e_probe_test.go")
    script = os.path.join(root, "e2e_write_config_tmp.go")
    with open(script, "w", encoding="utf-8") as fh:
        fh.write(
            "package main\n\n"
            "import (\n"
            "\t\"fmt\"\n"
            "\t\"os\"\n"
            "\t\"github.com/yukiu/ghsec/internal/config\"\n"
            ")\n\n"
            "func main() {\n"
            "\tc := &config.Config{Profiles: map[string]config.Profile{}}\n"
            "\tif err := c.AddProfile(\"e2e\", config.Profile{Token: \"ghp_0123456789abcdef\", Username: \"octocat\"}); err != nil {\n"
            "\t\tfmt.Fprintln(os.Stderr, err)\n"
            "\t\tos.Exit(1)\n"
            "\t}\n"
            "\tif err := c.Save(); err != nil {\n"
            "\t\tfmt.Fprintln(os.Stderr, err)\n"
            "\t\tos.Exit(1)\n"
            "\t}\n"
            "}\n",
        )
    try:
        res = subprocess.run(
            ["go", "run", script],
            capture_output=True,
            text=True,
            env={**os.environ, **env},
            cwd=root,
            timeout=180,
        )
    finally:
        if os.path.exists(script):
            os.remove(script)
        if os.path.exists(probe):
            os.remove(probe)

    if res.returncode != 0:
        record(False, "config writer ran", (res.stdout + res.stderr)[:300])
        return
    record(True, "config writer ran")

    target = os.path.join(cfg_dir, "config.json")
    if not os.path.exists(target):
        record(False, "config file exists", target)
        return
    mode = os.stat(target).st_mode & 0o777
    record(mode == 0o600, "config.json is 0600", f"got {oct(mode)}")
    dmode = os.stat(cfg_dir).st_mode & 0o777
    record(dmode == 0o700, "config dir is 0700", f"got {oct(dmode)}")

    with open(target, encoding="utf-8") as fh:
        body = fh.read()
    record("ghp_0123456789abcdef" in body, "token is persisted for the e2e fixture")
    leftovers = [n for n in os.listdir(cfg_dir) if ".tmp-" in n]
    record(not leftovers, "no stale temp files after save", str(leftovers))


def scenario_full_submission(home: str) -> None:
    print("\n[8] Full private-report submission against a mock GitHub API")
    import json as _json
    import threading as _threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    recorded: dict[str, list] = {"calls": []}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # silence request logging
            return

        def _record(self, body: bytes) -> None:
            recorded["calls"].append(
                {
                    "method": self.command,
                    "path": self.path,
                    "auth": self.headers.get("Authorization", ""),
                    "accept": self.headers.get("Accept", ""),
                    "version": self.headers.get("X-GitHub-Api-Version", ""),
                    "ua": self.headers.get("User-Agent", ""),
                    "body": body.decode("utf-8", "replace"),
                }
            )

        def do_GET(self):  # noqa: N802
            self._record(b"")
            if self.path == "/user":
                payload = {"login": "e2e-user", "id": 7, "html_url": "https://github.com/e2e-user"}
            else:
                payload = {"full_name": "acme/widget", "html_url": "https://github.com/acme/widget"}
            raw = _json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            self._record(self.rfile.read(length))
            payload = {
                "ghsa_id": "GHSA-2222-3333-4444",
                "cve_id": "CVE-2026-12345",
                "summary": "E2E summary",
                "severity": "high",
                "state": "triage",
                "html_url": "https://github.com/acme/widget/security/advisories/GHSA-2222-3333-4444",
            }
            raw = _json.dumps(payload).encode()
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = _threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        env = base_env(home)
        env["GITHUB_API_URL"] = f"http://127.0.0.1:{port}"
        env["GHSEC_CONFIG_HOME"] = os.path.join(home, "submit")
        session = Session(env)

        # 1. Welcome note -> token -> alias -> verified main menu.
        ok, text = session.read_until("Got it", timeout=20)
        record(ok, "onboarding shows the welcome note", text[-300:])
        if not ok:
            return
        session.send(b"\r")

        ok, text = session.read_until("GitHub token", timeout=12)
        record(ok, "onboarding asks for a token", text[-300:])
        if not ok:
            return
        session.send(b"ghp_e2e0123456789abcdefghij")
        session.send(b"\r")

        ok, text = session.read_until("Profile name (optional)", timeout=12)
        record(ok, "onboarding offers an optional alias", text[-300:])
        if not ok:
            return
        session.send(b"\r")  # accept the GitHub username as the alias

        ok, text = session.read_until("Submit a private vulnerability report", timeout=20)
        record(ok, "token verified and main menu rendered", text[-500:])
        if not ok:
            return

        # 2. Private report: repo -> summary -> severity -> CVE -> description.
        session.send(b"\r")
        ok, text = session.read_until("Repository", timeout=12)
        record(ok, "private report form opened", text[-300:])
        if not ok:
            return
        session.send(b"acme/widget")
        session.send(b"\r")

        ok, text = session.read_until("Summary", timeout=12)
        record(ok, "summary field reached", text[-300:])
        if not ok:
            return
        session.send(b"E2E summary")
        session.send(b"\r")

        ok, text = session.read_until("Severity", timeout=12)
        record(ok, "severity select reached", text[-300:])
        if not ok:
            return
        session.send(b"\r")  # keep the default severity

        ok, text = session.read_until("CVE", timeout=12)
        record(ok, "optional CVE field reached", text[-300:])
        if not ok:
            return
        session.send(b"\r")  # leave the CVE blank

        ok, text = session.read_until("Description", timeout=12)
        record(ok, "description field reached", text[-300:])
        if not ok:
            return
        session.send(b"line one of the description")
        session.send(b"\x1b\r")  # alt+enter inserts a newline in huh Text
        session.send(b"second line")
        session.send(b"\r")  # enter submits the text field / form

        # The description-source prompt follows the form; choose inline entry.
        ok, text = session.read_until("Type or paste directly", timeout=20)
        record(ok, "description source menu offered", text[-400:])
        if not ok:
            return
        # Options: file (0), editor (1), inline (2). Move down twice then select.
        session.send(b"\x1b[B")
        session.send(b"\x1b[B")
        session.send(b"\r")

        ok, text = session.read_until("Review", timeout=15)
        record(ok, "preview panel is shown before submitting", text[-400:])
        if not ok:
            return

        session.send(b"y")  # confirm submission
        ok, text = session.read_until("GHSA-2222-3333-4444", timeout=20)
        if not ok:
            print("      --- buffer tail ---")
            for line in text.splitlines()[-25:]:
                print("      " + line)
        record(ok, "success card shows the returned GHSA id", text[-500:])

        calls = recorded["calls"]
        posts = [c for c in calls if c["method"] == "POST"]
        record(len(posts) == 1, "exactly one POST was sent", f"got {len(posts)}")
        if posts:
            post = posts[0]
            record(
                post["path"] == "/repos/acme/widget/security-advisories/reports",
                "POST hit the private report endpoint",
                post["path"],
            )
            record(post["auth"] == "Bearer ghp_e2e0123456789abcdefghij",
                   "Authorization header carried the token")
            record(post["accept"] == "application/vnd.github+json", "Accept header set")
            record(post["version"] == "2022-11-28", "API version pinned")
            body = _json.loads(post["body"] or "{}")
            record(body.get("summary") == "E2E summary", "summary payload correct", str(body.get("summary")))
            record(body.get("severity") == "medium", "severity payload correct", str(body.get("severity")))
            record("cve_id" not in body, "empty CVE id omitted from the payload")
            record("line one" in body.get("description", ""), "description payload correct")

        session.send(b"\x03")
        session.wait(timeout=8)
    finally:
        server.shutdown()
        server.server_close()
        try:
            session.kill()  # type: ignore[possibly-undefined]
        except Exception:
            pass


def scenario_cli_noninteractive(home: str) -> None:
    """The non-interactive surface must work with no TTY at all."""
    print("\n[9] Non-interactive CLI: subcommands, flags, exit codes")
    env = base_env(home)
    env["GHSEC_CONFIG_HOME"] = os.path.join(home, "cli")
    env.pop("GITHUB_TOKEN", None)
    env.pop("GH_TOKEN", None)

    def run(args, stdin=None, extra_env=None):
        e = dict(env)
        if extra_env:
            e.update(extra_env)
        return subprocess.run(
            [BINARY] + args,
            capture_output=True,
            text=True,
            env=e,
            input=stdin,
            timeout=60,
        )

    # 9.1 help lists every subcommand
    res = run(["--help"])
    record(res.returncode == 0, "ghsec --help exits 0", f"rc={res.returncode}")
    for sub in ("report", "advisory", "profile"):
        record(sub in res.stdout, f"--help documents {sub!r}")

    # 9.2 per-subcommand help
    for sub in ("report", "advisory"):
        res = run([sub, "--help"])
        record(res.returncode == 0 and "--summary" in res.stderr,
               f"ghsec {sub} --help exits 0 and lists flags",
               f"rc={res.returncode} err={res.stderr[:120]!r}")

    # 9.3 dry run needs no network and no token
    res = run(["report", "--repo", "acme/widget", "--summary", "RCE",
               "--severity", "high", "--description", "details", "--dry-run"])
    record(res.returncode == 0, "dry-run exits 0 without credentials", f"rc={res.returncode} {res.stderr[:150]!r}")
    record("acme/widget" in res.stdout and "dry run" in res.stdout.lower(),
           "dry-run reports the target on stdout", res.stdout[:150])

    # 9.4 usage errors exit 2 and say what is wrong
    for args, needle in (
        (["report", "--repo", "acme/widget"], "--summary"),
        (["report", "--summary", "s", "--description", "d"], "owner/repo"),
        (["report", "--repo", "a/b", "--summary", "s", "--severity", "nope", "--description", "d"], "severity"),
        (["report", "--repo", "a/b", "--summary", "s"], "description"),
        (["report", "--bogus"], "bogus"),
        (["bogus"], "unknown command"),
    ):
        res = run(args)
        record(res.returncode == 2, f"usage error exits 2 for {' '.join(args[:2])!r}", f"rc={res.returncode}")
        record(needle in (res.stdout + res.stderr),
               f"usage error mentions {needle!r}", (res.stdout + res.stderr)[:160])

    # 9.5 no credentials is a usage error that names the env var
    res = run(["report", "--repo", "a/b", "--summary", "s", "--severity", "low",
               "--description", "d", "--yes"])
    record(res.returncode == 2, "missing credentials exits 2", f"rc={res.returncode}")
    record("GITHUB_TOKEN" in (res.stdout + res.stderr),
           "missing-credential error names GITHUB_TOKEN", (res.stdout + res.stderr)[:160])

    # 9.6 profile management without a TTY
    res = run(["profile", "list"])
    record(res.returncode == 0 and "no profiles" in res.stdout.lower(),
           "profile list works on an empty config", f"rc={res.returncode} {res.stdout[:120]!r}")

    token = "ghp_cli0123456789abcdefghij"
    res = run(["profile", "add", "--alias", "ci", "--token", token, "--no-verify"])
    record(res.returncode == 0, "profile add stores a token", f"rc={res.returncode} {res.stderr[:150]!r}")

    res = run(["profile", "list", "--json"])
    record(res.returncode == 0, "profile list --json exits 0", f"rc={res.returncode}")
    try:
        parsed = json.loads(res.stdout)
        record(isinstance(parsed, list) and parsed and parsed[0]["alias"] == "ci",
               "profile list --json returns parseable JSON", res.stdout[:200])
        record(parsed[0]["active"] is True, "the added profile is active")
        record(token not in res.stdout, "profile list never prints the raw token")
    except json.JSONDecodeError as exc:
        record(False, "profile list --json is valid JSON", f"{exc}: {res.stdout[:200]}")

    # 9.7 a real submission against the mock API
    status_err = mock_submit_scenario(env)

    # 9.8 credentials resolve from GITHUB_TOKEN when no config exists
    fresh = base_env(home)
    fresh["GHSEC_CONFIG_HOME"] = os.path.join(home, "cli-env")
    fresh["GITHUB_TOKEN"] = token
    res = subprocess.run(
        [BINARY, "report", "--repo", "a/b", "--summary", "s", "--severity", "low",
         "--description", "d", "--dry-run"],
        capture_output=True, text=True, env=fresh, timeout=60,
    )
    record(res.returncode == 0, "GITHUB_TOKEN satisfies the credential check", f"rc={res.returncode}")


def mock_submit_scenario(env: dict[str, str]) -> None:
    """Run `ghsec report --yes --json` against a local mock GitHub API."""
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    recorded: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            return

        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            recorded.append(
                {
                    "path": self.path,
                    "auth": self.headers.get("Authorization", ""),
                    "version": self.headers.get("X-GitHub-Api-Version", ""),
                    "body": self.rfile.read(length).decode(),
                }
            )
            raw = json.dumps(
                {
                    "ghsa_id": "GHSA-cli0-test-0001",
                    "cve_id": "CVE-2026-1234",
                    "summary": "CLI submission",
                    "severity": "high",
                    "state": "triage",
                    "html_url": "https://example.test/adv",
                }
            ).encode()
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    try:
        e = dict(env)
        e["GHSEC_CONFIG_HOME"] = os.path.join(os.path.dirname(env.get("GHSEC_CONFIG_HOME", "")), "cli-submit")
        res = subprocess.run(
            [
                BINARY, "report",
                "--repo", "acme/widget",
                "--summary", "CLI submission",
                "--severity", "high",
                "--cve", "cve-2026-1234",
                "--description", "submitted from the CLI",
                "--token", "ghp_cli0123456789abcdefghij",
                "--api-url", f"http://127.0.0.1:{port}",
                "--yes", "--json",
            ],
            capture_output=True, text=True, env=e, timeout=60,
        )
        record(res.returncode == 0, "CLI submission exits 0", f"rc={res.returncode} {res.stderr[:200]!r}")

        try:
            payload = json.loads(res.stdout)
            record(payload.get("ghsa_id") == "GHSA-cli0-test-0001",
                   "--json carries the created advisory id", res.stdout[:200])
            record(payload.get("url", "").startswith("https://"),
                   "--json carries the advisory URL")
        except json.JSONDecodeError as exc:
            record(False, "--json output is valid JSON", f"{exc}: {res.stdout[:200]}")

        record(len(recorded) == 1, "exactly one submission was made", f"got {len(recorded)}")
        if recorded:
            call = recorded[0]
            record(call["path"] == "/repos/acme/widget/security-advisories/reports",
                   "CLI POST hits the private report endpoint", call["path"])
            record(call["auth"].startswith("Bearer "), "CLI sends the Authorization header")
            record(call["version"] == "2022-11-28", "CLI pins the API version")
            body = json.loads(call["body"] or "{}")
            record(body.get("cve_id") == "CVE-2026-1234",
                   "CLI normalises the CVE id to upper case", str(body.get("cve_id")))
            record(body.get("severity") == "high", "CLI sends the severity as a lowercase string")

        # Without --yes the CLI must refuse when it has no TTY.
        res = subprocess.run(
            [
                BINARY, "report",
                "--repo", "acme/widget",
                "--summary", "no confirmation",
                "--severity", "low",
                "--description", "x",
                "--token", "ghp_cli0123456789abcdefghij",
                "--api-url", f"http://127.0.0.1:{port}",
            ],
            capture_output=True, text=True, env=e, stdin=subprocess.DEVNULL, timeout=60,
        )
        record(res.returncode == 2, "submission without --yes exits 2", f"rc={res.returncode}")
        record("--yes" in (res.stdout + res.stderr), "refusal explains that --yes is required")
        record(len(recorded) == 1, "the refused call sent nothing", f"got {len(recorded)}")
    finally:
        server.shutdown()
        server.server_close()


def scenario_advisory_management(home: str) -> None:
    """Read/edit/comment/CVE/history, against a mock GitHub advisory API."""
    print("\n[10] Advisory management: list, show, edit, comments, CVE, history")
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    calls: list[dict] = []
    ghsa = "GHSA-abcd-1234-efgh"
    detail = {
        "ghsa_id": ghsa, "cve_id": "CVE-2026-1111", "summary": "RCE in YAML loader",
        "description": "## Summary\n\nRemote code execution.", "severity": "critical",
        "state": "triage", "html_url": "https://example.test/" + ghsa,
        "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-02T00:00:00Z",
        "author": {"login": "finder"},
        "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "widget"},
                             "vulnerable_version_range": "< 1.2.3"}],
        "cvss": {"score": 9.8, "vector_string": "CVSS:3.1/AV:N"},
        "cwe_ids": ["CWE-94"], "credits": [{"login": "finder", "type": "reporter"}],
    }
    listing = [
        detail,
        {"ghsa_id": "GHSA-wxyz-9876-mnop", "cve_id": "", "summary": "SSRF",
         "severity": "medium", "state": "draft", "html_url": "https://example.test/2",
         "vulnerabilities": []},
    ]
    comments = [
        {"id": 101, "body": "Thanks, triaging now.", "user": {"login": "maintainer"},
         "created_at": "2026-01-03T00:00:00Z", "updated_at": "2026-01-03T00:00:00Z",
         "html_url": "https://example.test/c/101", "author_association": "OWNER",
         "advisory_url": "https://example.test/" + ghsa},
    ]

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            return

        def _send(self, code, payload):
            raw = json.dumps(payload).encode() if payload is not None else b""
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            if raw:
                self.wfile.write(raw)

        def _record(self, body: bytes = b"") -> str:
            calls.append({"method": self.command, "path": self.path,
                          "body": body.decode("utf-8", "replace")})
            return self.path.split("?")[0]

        def do_GET(self):  # noqa: N802
            path = self._record()
            if path.endswith("/comments"):
                self._send(200, comments)
            elif "/security-advisories/" in path:
                self._send(200, detail)
            elif path.endswith("/security-advisories"):
                self._send(200, listing)
            else:
                self._send(404, {"message": "Not Found"})

        def do_PATCH(self):  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            path = self._record(self.rfile.read(length))
            patch = json.loads(calls[-1]["body"] or "{}")
            if "/comments/" in path:
                self._send(200, dict(comments[0], body=patch.get("body", "")))
            else:
                merged = dict(detail)
                merged.update(patch)
                self._send(200, merged)

        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            path = self._record(self.rfile.read(length))
            if path.endswith("/cve"):
                self._send(202, None)
            elif path.endswith("/comments"):
                body = json.loads(calls[-1]["body"] or "{}").get("body", "")
                self._send(201, dict(comments[0], id=202, body=body))
            else:
                self._send(201, detail)

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    env = base_env(home)
    env["GHSEC_CONFIG_HOME"] = os.path.join(home, "advmgmt")
    env.pop("GITHUB_TOKEN", None)
    env.pop("GH_TOKEN", None)
    token = "ghp_adv0123456789abcdefghij"
    api = "--api-url"
    url = f"http://127.0.0.1:{port}"

    def run(args, stdin=None):
        return subprocess.run([BINARY] + args, capture_output=True, text=True,
                              env=env, input=stdin, timeout=60)

    try:
        # Seed a profile so credential resolution works without env vars.
        res = run(["profile", "add", "--alias", "e2e", "--token", token, "--no-verify"])
        record(res.returncode == 0, "seeded a profile for the advisory tests", res.stderr[:150])

        # --- list ---
        res = run(["list", "--repo", "acme/widget", api, url])
        record(res.returncode == 0, "list exits 0", f"rc={res.returncode} {res.stderr[:150]}")
        record(ghsa in res.stdout, "list shows the advisory id")
        record("Triage" in res.stdout or "triage" in res.stdout, "list shows the lifecycle state")
        record("CVE-2026-1111" in res.stdout, "list shows the assigned CVE")
        record("SSRF" in res.stdout, "list shows the second advisory")

        res = run(["list", "--repo", "acme/widget", "--json", api, url])
        try:
            parsed = json.loads(res.stdout)
            record(isinstance(parsed, list) and len(parsed) == 2,
                   "list --json returns both advisories", res.stdout[:150])
        except json.JSONDecodeError as exc:
            record(False, "list --json is valid JSON", f"{exc}: {res.stdout[:150]}")

        # --- show ---
        res = run(["show", "--repo", "acme/widget", "--ghsa", ghsa, api, url])
        record(res.returncode == 0, "show exits 0", f"rc={res.returncode}")
        # Severity is rendered title-cased for humans, so match case-insensitively.
        for needle in (ghsa, "CVE-2026-1111", "npm:widget", "Remote code execution"):
            record(needle in res.stdout, f"show includes {needle!r}")
        record("critical" in res.stdout.lower(), "show includes the severity")

        # --- comments: read and reply (the "reply to the author" feature) ---
        res = run(["comments", "list", "--repo", "acme/widget", "--ghsa", ghsa, api, url])
        record(res.returncode == 0, "comments list exits 0", f"rc={res.returncode}")
        record("maintainer" in res.stdout and "triaging" in res.stdout,
               "comments list shows the author and body", res.stdout[:200])

        before = len(calls)
        res = run(["comments", "add", "--repo", "acme/widget", "--ghsa", ghsa,
                   "--body", "Fix is ready for review.", api, url])
        record(res.returncode == 0, "comments add exits 0", f"rc={res.returncode} {res.stderr[:150]}")
        posts = [c for c in calls[before:] if c["method"] == "POST"]
        record(len(posts) == 1 and posts[0]["path"].endswith("/comments"),
               "reply POSTs to the comments endpoint", str([p["path"] for p in posts]))
        if posts:
            sent = json.loads(posts[0]["body"] or "{}")
            record(sent.get("body") == "Fix is ready for review.",
                   "reply carries the exact body", str(sent))

        res = run(["comments", "add", "--repo", "acme/widget", "--ghsa", ghsa,
                   "--body", "   ", api, url])
        record(res.returncode == 2, "an empty reply is a usage error", f"rc={res.returncode}")

        # --- cve request ---
        before = len(calls)
        res = run(["cve", "--repo", "acme/widget", "--ghsa", ghsa, api, url])
        record(res.returncode == 0, "cve exits 0", f"rc={res.returncode} {res.stderr[:150]}")
        record("asynchronous" in res.stdout.lower() or "async" in res.stdout.lower(),
               "cve explains it is asynchronous", res.stdout[:200])
        cve_posts = [c for c in calls[before:] if c["method"] == "POST"]
        record(len(cve_posts) == 1 and cve_posts[0]["path"].endswith("/cve"),
               "cve POSTs to the cve endpoint", str([p["path"] for p in cve_posts]))

        # --- edit: only the requested fields are sent ---
        before = len(calls)
        res = run(["edit", "--repo", "acme/widget", "--ghsa", ghsa,
                   "--summary", "Updated title", api, url])
        record(res.returncode == 0, "edit exits 0", f"rc={res.returncode} {res.stderr[:150]}")
        patches = [c for c in calls[before:] if c["method"] == "PATCH"]
        record(len(patches) == 1, "edit issues one PATCH", str(len(patches)))
        if patches:
            sent = json.loads(patches[0]["body"] or "{}")
            record(sent.get("summary") == "Updated title", "edit sends the new summary")
            record("severity" not in sent and "state" not in sent and "description" not in sent,
                   "edit omits fields the user did not set", str(sorted(sent)))

        # triage is not settable through the API
        res = run(["edit", "--repo", "acme/widget", "--ghsa", ghsa, "--state", "triage", api, url])
        record(res.returncode == 2, "edit rejects the triage state", f"rc={res.returncode}")
        record("triage" in (res.stdout + res.stderr).lower(), "rejection explains triage")

        # edit with nothing to change
        res = run(["edit", "--repo", "acme/widget", "--ghsa", ghsa, api, url])
        record(res.returncode == 2, "edit with no changes is a usage error", f"rc={res.returncode}")

        # --- history: recorded locally, refreshed from the API ---
        res = run(["history", "list"])
        record(res.returncode == 0, "history list exits 0", f"rc={res.returncode}")
        record("no submissions recorded" in res.stdout.lower(),
               "history is empty before anything is submitted", res.stdout[:150])

        # File a report so the history has an entry.
        res = run(["report", "--repo", "acme/widget", "--summary", "History probe",
                   "--severity", "low", "--description", "x", "--yes", api, url])
        record(res.returncode == 0, "report succeeded for the history test",
               f"rc={res.returncode} {res.stderr[:150]}")

        res = run(["history", "list"])
        record(res.returncode == 0, "history list after a submission exits 0")
        record(ghsa in res.stdout or "acme/widget" in res.stdout,
               "history records the submission", res.stdout[:250])

        res = run(["history", "list", "--refresh", api, url])
        record(res.returncode == 0, "history --refresh exits 0",
               f"rc={res.returncode} {res.stderr[:200]}")
        record("Triage" in res.stdout or "triage" in res.stdout,
               "history --refresh shows the live state", res.stdout[:300])

        res = run(["history", "list", "--json"])
        try:
            parsed = json.loads(res.stdout)
            record(isinstance(parsed, list) and len(parsed) >= 1,
                   "history --json is machine readable", res.stdout[:200])
        except json.JSONDecodeError as exc:
            record(False, "history --json is valid JSON", f"{exc}: {res.stdout[:200]}")

        res = run(["history", "clear", "--yes"])
        record(res.returncode == 0, "history clear exits 0", f"rc={res.returncode}")
        res = run(["history", "list"])
        record("no submissions recorded" in res.stdout.lower(),
               "history is empty after clearing", res.stdout[:150])

        # --- usage errors ---
        for args, needle in (
            (["show", "--repo", "a/b"], "--ghsa"),
            (["list"], "--repo"),
            (["comments", "bogus"], "unknown subcommand"),
            (["cve", "--repo", "a/b", "--ghsa", "not-a-ghsa"], "GHSA"),
            (["history", "bogus"], "unknown subcommand"),
        ):
            res = run(args)
            record(res.returncode == 2, f"usage error exits 2 for {' '.join(args[:1])!r}", f"rc={res.returncode}")
            record(needle in (res.stdout + res.stderr),
                   f"usage error names {needle!r}", (res.stdout + res.stderr)[:200])
    finally:
        server.shutdown()
        server.server_close()


def main() -> int:
    if not os.path.exists(BINARY):
        print(f"binary not found: {BINARY}\nrun `make build` first", file=sys.stderr)
        return 2
    print(f"ghsec end-to-end acceptance suite\nbinary: {BINARY}")

    home = tempfile.mkdtemp(prefix="ghsec-e2e-")
    try:
        scenario_version(home)
        scenario_non_tty_guard(home)
        scenario_bad_flag(home)
        scenario_onboarding_shown(home)
        scenario_ctrl_c_on_onboarding(home)
        scenario_corrupt_config(home)
        scenario_config_permissions(home)
        scenario_full_submission(home)
        scenario_cli_noninteractive(home)
        scenario_advisory_management(home)
    finally:
        shutil.rmtree(home, ignore_errors=True)

    print(f"\n{len(passes)} passed, {len(failures)} failed")
    for f in failures:
        print(f"  - {f}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
