# ghsec

[![CI](https://github.com/yuuuuukiu/ghsec/actions/workflows/ci.yml/badge.svg)](https://github.com/yuuuuukiu/ghsec/actions/workflows/ci.yml)
[![Release](https://github.com/yuuuuukiu/ghsec/actions/workflows/release.yml/badge.svg)](https://github.com/yuuuuukiu/ghsec/actions/workflows/release.yml)
[![Latest release](https://img.shields.io/github/v/release/yuuuuukiu/ghsec)](https://github.com/yuuuuukiu/ghsec/releases/latest)
[![Go version](https://img.shields.io/github/go-mod/go-version/yuuuuukiu/ghsec)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`ghsec` is a cross-platform terminal UI for **GitHub Security Advisories**. It lets security
researchers file private vulnerability reports and lets maintainers draft repository advisories
without leaving the shell — no runtime, no browser, no copy-pasting tokens into web forms.

```text
  ██████╗ ██╗  ██╗███████╗███████╗ ██████╗
 ██╔════╝ ██║  ██║██╔════╝██╔════╝██╔════╝
 ██║  ███╗███████║███████╗█████╗  ██║
 ██║   ██║██╔══██║╚════██║██╔══╝  ██║
 ╚██████╔╝██║  ██║███████║███████╗╚██████╗
  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝
  GitHub Security Advisories, from your terminal
```

## Features

| Area | What you get |
|---|---|
| **Onboarding** | First run detects a missing config, asks for a PAT (masked input) and verifies it against `GET /user`. The GitHub login becomes the profile alias unless you override it. |
| **Profiles** | Multiple tokens stored side by side. List (masked + active badge), switch, add, delete. Switching always re-verifies the token before persisting. |
| **Private reports** | `POST /repos/{owner}/{repo}/security-advisories/reports` with summary, severity, optional CVE and a Markdown description. |
| **Maintainer drafts** | `POST /repos/{owner}/{repo}/security-advisories` including affected version ranges. |
| **Description input** | Type inline, read a local Markdown/TXT file, or open `$VISUAL` / `$EDITOR` (defaults to `nano`, `vim`, or `notepad` on Windows). |
| **Markdown preview** | Descriptions are rendered with `glamour` and shown in a bordered panel for a final `y/N` confirmation before anything leaves your machine. |
| **Advisory browser** | Browse a repository's advisories with lifecycle state, severity, CVE progress, affected packages and the full comment thread — then reply, request a CVE, or edit in place. |
| **Edit & collaborate** | Update summary, description, severity, state, CVE id, CWE ids and CVSS vector. Reply to the reporter or maintainers on the advisory thread. |
| **Submission history** | `ghsec history` lists what you filed from this machine and `--refresh` pulls each entry's live state and assigned CVE from GitHub. |
| **Pre-flight check** | Before submitting a report, `ghsec` asks GitHub whether the repository accepts private vulnerability reports (`/private-vulnerability-reporting`) and warns you early if it does not. |
| **Error handling** | 401/403/404/422/5xx map to human-readable guidance, never raw JSON or a panic. |
| **GitHub Enterprise** | Set `GITHUB_API_URL` (same variable GitHub Actions uses) to target a GHES instance. |

## Install

### One line

```sh
# macOS and Linux
curl -fsSL https://raw.githubusercontent.com/yuuuuukiu/ghsec/main/install.sh | sh
```

```powershell
# Windows (PowerShell)
irm https://raw.githubusercontent.com/yuuuuukiu/ghsec/main/install.ps1 | iex
```

The installers detect your platform, download the matching release archive, **verify
its SHA-256 against the published `SHA256SUMS`**, and drop a single binary on your
`PATH`. They never use `sudo` and never edit your shell profile.

Pin a version or choose the directory with environment variables:

```sh
GHSEC_VERSION=v1.0.0 GHSEC_INSTALL_DIR="$HOME/bin" \
  curl -fsSL https://raw.githubusercontent.com/yuuuuukiu/ghsec/main/install.sh | sh
```

### Supported platforms

Every release ships these builds, each statically linked (`CGO_ENABLED=0`), stripped
with `-ldflags="-s -w"`, and free of any Go, Python or Node runtime dependency:

| Platform | Architecture | Archive |
|---|---|---|
| macOS | Apple Silicon (arm64) | `ghsec_<version>_darwin_arm64.tar.gz` |
| macOS | Intel (amd64) | `ghsec_<version>_darwin_amd64.tar.gz` |
| Linux | x86-64 (amd64) | `ghsec_<version>_linux_amd64.tar.gz` |
| Linux | arm64 | `ghsec_<version>_linux_arm64.tar.gz` |
| Windows | x86-64 (amd64) | `ghsec_<version>_windows_amd64.zip` |
| Windows | arm64 | `ghsec_<version>_windows_arm64.zip` |

Browse them on the [releases page](https://github.com/yuuuuukiu/ghsec/releases).
Each archive contains the binary plus `LICENSE` and `README.md`.

### From source

```bash
go install github.com/yuuuuukiu/ghsec/cmd/ghsec@latest

# or clone and build every target locally
make build-all     # -> dist/ghsec-{darwin,linux,windows}-{amd64,arm64}
make size          # artefact table + ~15 MB budget check
```

### Verify a manual download

```sh
sha256sum -c SHA256SUMS --ignore-missing    # Linux
shasum -a 256 -c SHA256SUMS                 # macOS
```

## Usage

`ghsec` works two ways: an interactive TUI, and a scriptable CLI. With no
arguments you get the TUI; any argument selects the non-interactive surface.

```bash
# interactive
ghsec

# non-interactive (scripts, CI, cron)
ghsec report   --repo OWNER/REPO --summary "…" --description-file advisory.md --yes
ghsec advisory --repo OWNER/REPO --summary "…" --severity high --affected "<= 1.4.2" --yes
ghsec profile  list
ghsec --version
ghsec --help
```

### Non-interactive CLI

| Command | Purpose |
|---|---|
| `ghsec report` | file a private vulnerability report |
| `ghsec advisory` | create a maintainer advisory draft |
| `ghsec list` | list a repository's advisories and their status |
| `ghsec show` | show one advisory in full |
| `ghsec edit` | update an existing advisory |
| `ghsec comments list\|add\|update` | read replies and post your own |
| `ghsec cve` | request a CVE id for an advisory |
| `ghsec history list\|clear` | review your submissions and their live status |
| `ghsec profile list\|use\|add\|remove` | manage stored API keys |

Shared flags for `report` and `advisory`:

| Flag | Meaning |
|---|---|
| `--repo OWNER/REPO` | target repository (required, validated) |
| `--summary TEXT` | one-line summary (required, ≤256 chars) |
| `--severity LEVEL` | `critical`, `high`, `medium` (default) or `low` |
| `--description TEXT` | inline description body |
| `--description-file PATH` | read the body from a file, or `-` for stdin |
| `--cve CVE-YYYY-NNNN` | optional, normalised to upper case |
| `--affected "…"` | `advisory` only: affected version ranges |
| `--token` / `--profile` | choose the credential explicitly |
| `--api-url URL` | GitHub Enterprise Server API root |
| `--yes` | required when not attached to a terminal |
| `--json` | machine-readable result on stdout |
| `--dry-run` | validate and print the target, send nothing |
| `--timeout 60s` | request timeout |

Credential precedence: `--token` → `$GITHUB_TOKEN` → `$GH_TOKEN` → the stored
profile (`--profile`, else the active one). CI therefore needs no config file.

Streams and exit codes are stable for scripting: **stdout** carries the result
(GHSA id, URL, or JSON), **stderr** carries diagnostics.

```text
0    success
1    runtime failure (network, API, GitHub rejection)
2    invalid usage (bad flags, missing input, missing credentials, no --yes)
130  interrupted (Ctrl+C)
```

#### Managing advisories after submission

```bash
# What did I file, and where does it stand now?
ghsec history list --refresh

# Everything in the repo, newest first
ghsec list --repo OWNER/REPO --state published

# Inspect one advisory, including its CVE progress
ghsec show --repo OWNER/REPO --ghsa GHSA-xxxx-yyyy-zzzz

# Read the thread and reply to the reporter
ghsec comments list --repo OWNER/REPO --ghsa GHSA-xxxx-yyyy-zzzz
ghsec comments add  --repo OWNER/REPO --ghsa GHSA-xxxx-yyyy-zzzz \
                    --body "Thanks — a fix is in review."

# Ask GitHub to issue a CVE (asynchronous: no id is returned immediately)
ghsec cve --repo OWNER/REPO --ghsa GHSA-xxxx-yyyy-zzzz

# Update fields in place; only the flags you pass are sent
ghsec edit --repo OWNER/REPO --ghsa GHSA-xxxx-yyyy-zzzz \
           --severity critical --state draft --cve ""

# Preview a patch without touching GitHub
ghsec edit --repo OWNER/REPO --ghsa GHSA-xxxx-yyyy-zzzz --summary "New title" --dry-run
```

`edit` uses pointer semantics: only the flags you actually pass are transmitted, so
`--cve ""` clears the CVE id while omitting `--cve` leaves it untouched. GitHub accepts
`draft`, `published` and `closed` as target states; `triage` is assigned by GitHub and
is rejected locally with an explanation.

> **Note on CVE status.** GitHub exposes a CVE *request* endpoint (which returns `202`
> Accepted) but no field stating "a CVE was requested". A CVE id appearing on the advisory
> is the observable signal that one was issued, so `ghsec` reports exactly that rather
> than inventing a status.

> **Note on history.** GitHub's REST API has no "reports I filed" listing — the reports
> endpoint is `POST`-only. `ghsec history` therefore keeps a local index of what this
> machine submitted (identifiers only, never the token) and re-reads the authoritative
> state from GitHub via `--refresh`.

```bash
# typical CI use: fail the job if the report is rejected
echo "$ADVISORY_MD" | ghsec report \
  --repo "$REPO" --summary "RCE in YAML loader" --severity high \
  --description-file - --yes --json | jq -r .ghsa_id
```

On first launch you are walked through token creation:

1. Open <https://github.com/settings/tokens>.
2. Create a **classic** token with the `repo` scope
   (or `public_repo` for open-source-only use).
   For fine-grained tokens, grant **Repository permissions → Security events: Read and write**.
3. Paste it into the prompt. `ghsec` verifies it immediately and stores it with `0600` permissions.

### Menu

```text
❯ Submit a private vulnerability report
  Create a security advisory draft (maintainer)
  Manage API keys / profiles
  Exit
```

`Ctrl+C` at any prompt aborts cleanly: nothing is written, nothing is half-saved.

**Safety guard:** a non-interactive invocation without `--yes` is refused with
exit code 2 rather than submitting. A forgotten flag or an accidental pipe can
never file a vulnerability report on your behalf.

## Configuration

| Platform | Path |
|---|---|
| Linux / macOS (XDG) | `$XDG_CONFIG_HOME/ghsec/config.json`, falling back to `~/.config/ghsec/config.json` |
| macOS (default `UserConfigDir`) | `~/Library/Application Support/ghsec/config.json` when `XDG_CONFIG_HOME` is unset |
| Windows | `%APPDATA%\ghsec\config.json` |
| Any | `$GHSEC_CONFIG_HOME` overrides everything |

Set `GITHUB_API_URL` to point at GitHub Enterprise Server (default `https://api.github.com`).

```json
{
  "active_profile": "work",
  "profiles": {
    "work": {
      "token": "ghp_xxxxxxxxxxxxxxxxxxxx",
      "username": "octocat"
    }
  }
}
```

The file is written atomically (temp file + `fsync` + rename) and forced to mode `0600`; the
directory is forced to `0700`. Tokens are shown as `ghp_****1234` everywhere in the UI.

> **Security note** — storage is plaintext JSON protected by filesystem permissions. This matches
> `gh` CLI and `git-credential-store`. If you need at-rest encryption, use full-disk encryption or
> point `$GHSEC_CONFIG_HOME` at an encrypted volume / ephemeral tmpfs.

## Project layout

```text
ghsec/
├── cmd/ghsec/main.go        # entrypoint, dispatch, menu loop, flow orchestration
├── cmd/ghsec/cli.go         # non-interactive report/advisory/profile commands
├── cmd/ghsec/cli_advisories.go # list/show/edit/comments/cve commands
├── cmd/ghsec/cli_history.go # local submission history + status refresh
├── internal/api/            # GitHub REST client, advisory endpoints, error mapping
├── internal/config/         # cross-platform paths, atomic 0600 persistence, profiles
├── internal/editor/         # $VISUAL/$EDITOR invocation, file reading, multi-line input
├── internal/tui/            # huh forms & menus, lipgloss theme, glamour previews
│   └── browse.go            # advisory browser, detail view, comment thread
├── Makefile                 # build / test / cross-compile / checksums
├── docs/ACCEPTANCE.md       # acceptance criteria → evidence
├── docs/CONTRACT.md         # internal interface contract
└── scripts/
    ├── e2e.py               # PTY-driven acceptance suite
    └── check-size.sh        # ~15 MB binary budget
```

## Development

```bash
make check      # gofmt check + go vet + unit tests
make test-race  # race detector
make build      # host binary in dist/
make build-all  # six release targets
make size       # sizes + ~15 MB budget enforcement
make e2e        # PTY-driven acceptance suite (needs python3)
make accept     # everything above, in order

make release VERSION=v1.0.0      # build all platform archives + SHA256SUMS locally
make release-tag VERSION=v1.0.0  # tag and push, which publishes the release
```

### Releasing

Pushing a `v*` tag triggers `.github/workflows/release.yml`, which runs the test
suite, builds all six platform archives with the same `scripts/build-release.sh`
used locally, and publishes them with a `SHA256SUMS` file and the installers:

```bash
make release-tag VERSION=v1.0.0
```

`ci.yml` runs gofmt, `go vet`, `go test -race` on Linux/macOS/Windows, the
PTY acceptance suite on Linux and macOS, and the cross-compile + size budget
check, so a broken commit cannot reach a tag.

`make e2e` drives the real binary through a pseudo-terminal: it walks onboarding,
interrupts it with `Ctrl+C`, feeds a corrupt config, checks `0600`/`0700`
permissions, and performs a full private-report submission against a local mock
GitHub API — asserting the exact endpoint, headers and JSON payload. It runs
offline and never touches a real token.

The test suite uses only the standard library (`httptest`, `t.TempDir`), so it runs offline and
never touches a real GitHub token.

## Licence

MIT
