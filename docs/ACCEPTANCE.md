# ghsec — Acceptance Test Record

Acceptance criteria from the specification and how each is verified.

| # | Criterion | Status | Evidence |
|---|---|---|---|
| 1 | **Zero external runtime** — runs with no Go/Python on the target | PASS | `CGO_ENABLED=0`; `file` reports `ELF ... statically linked, stripped` for Linux; macOS links only system libraries; 6 standalone artefacts from `make build-all` |
| 2 | **First-run onboarding + exit protection** — no config ⇒ forced onboarding; `Ctrl+C` exits gracefully with no dirty config | PASS | PTY suite scenarios [3] and [4]: onboarding renders, no config file before verification, exit code 130 on `Ctrl+C`, config dir absent afterwards |
| 3 | **API fault tolerance** — bad specs / missing repos show friendly errors, never a panic or raw log | PASS | `go test ./internal/api` covers 401/403/404/422/5xx → `FriendlyMessage`; `ValidateRepoSpec` table tests; scenario [8] asserts a missing/invalid repo triggers guidance |
| 4 | **Single-file size ~15 MB** after `-ldflags="-s -w"` | PASS | 14.13–15.25 MiB across the six targets; `make size` / `scripts/check-size.sh` enforces a 16 MiB hard cap |

Live verification against the real GitHub API (unauthenticated, read-only):

```text
$ go run ./probe   # GetRepository("cli","cli")
repo=cli/cli full_name=https://github.com/cli/cli private=false advisory_enabled=true

$ curl -s https://api.github.com/repos/cli/cli/private-vulnerability-reporting
{"enabled":true}
```

Both agree, confirming the endpoint path and decode logic are correct.

## Non-interactive CLI (added surface)

The original specification described a TUI only. A scriptable CLI was added so
the tool also works in CI and cron, without changing the TUI's behaviour when no
arguments are given. Verified by E2E scenario [9] (42 checks):

| Behaviour | Verified by |
|---|---|
| Subcommands exist and are documented | `--help` lists `report`, `advisory`, `profile`; each `--help` lists its flags |
| Usage errors exit 2 with a specific message | six malformed invocations, each asserting the exit code *and* the named missing input |
| Missing credentials name `GITHUB_TOKEN` | exits 2, mentions the env var |
| Credential precedence | unit tests: `--token` → `$GITHUB_TOKEN` → `$GH_TOKEN` → stored profile |
| `--dry-run` touches no network | zero requests recorded by the mock server |
| `--json` is valid, scriptable JSON | parsed with `json.loads`, asserts `ghsa_id`/`url` |
| Real submission works headless | POST to the mock API with the right path, `Bearer` header, pinned API version, upper-cased CVE, lowercase severity |
| A missing `--yes` fails safe | exit 2 and **no request sent** |
| No token leaks on stdout | `profile list` shows `ghp_****ghij` only |

Exit codes are part of the contract: `0` success, `1` runtime failure,
`2` invalid usage, `130` interrupted.

## Advisory management (added surface)

The second feature request asked for: submission history with live status, editing
everything the GitHub web UI can edit, full advisory-functionality parity, CVE
issuance status, author replies, and the ability to reply back.

Verified against the **official GitHub OpenAPI description** (`api.github.com`,
API version 2022-11-28) before any code was written — every endpoint below was
confirmed to exist, with its real request schema, rather than assumed:

| Endpoint | Verified method(s) |
|---|---|
| `/repos/{owner}/{repo}/security-advisories` | GET (list, `state` filter), POST |
| `/repos/{owner}/{repo}/security-advisories/{ghsa_id}` | GET, PATCH |
| `/repos/{owner}/{repo}/security-advisories/{ghsa_id}/comments` | GET, POST |
| `/repos/{owner}/{repo}/security-advisories/{ghsa_id}/comments/{id}` | GET, PATCH |
| `/repos/{owner}/{repo}/security-advisories/{ghsa_id}/cve` | POST (202 Accepted) |
| `/repos/{owner}/{repo}/security-advisories/reports` | **POST only** |

The last row is why history is local: there is no endpoint that lists the private
reports a user filed.

What the E2E suite asserts (scenario [10], 44 checks):

| Behaviour | Evidence |
|---|---|
| List advisories with status | `list` prints state, severity, GHSA, CVE, summary; `--json` parses to the right count |
| Full detail | `show` includes id, severity, CVE, affected package, description |
| Read replies | `comments list` shows author and body |
| **Reply to the author** | `comments add` POSTs to `/comments` with the exact `{"body": …}` payload; empty body is a usage error |
| CVE issuance | `cve` POSTs to `/cve`, exits 0 on 202, and states the assignment is asynchronous |
| Edit | one PATCH; only the flags passed appear in the body (`severity`/`state`/`description` absent); `--state triage` rejected; no-op edit rejected |
| History recorded | after a submission `history list` contains the entry |
| History refreshed | `history --refresh` shows the live state pulled from GitHub |
| History is disposable | `history clear --yes` empties it |
| Usage errors | six malformed invocations, each exit 2 with the specific cause named |

Two real defects were found by this verification and fixed:

1. **GHSA casing.** The API layer upper-cased the whole identifier
   (`GHSA-ABCD-1234-EFGH`), but GitHub's canonical form is an upper-case prefix with a
   lower-case suffix (`GHSA-qr28-fpjm-wq7f`, confirmed against the live API). This
   polluted URLs, rendered output and history entries. Now normalised to canonical form
   in one place (`api.ValidateGHSAID` / `normalizeGHSAID`) and shared by the CLI and TUI.
2. **Unrefreshable history entries.** The history recorder reverse-engineered
   `owner/repo` from a response URL, which failed whenever the URL shape differed,
   leaving entries with no repository — those could never be refreshed. The submitting
   command now passes the repository it already knows. A second bug in the same path
   resolved credentials from an empty flag set, so `--token`/`--api-url` were ignored
   and refresh failed with 401; it now uses the resolved client.

## Manual smoke test

```bash
# 1. fresh machine state
export GHSEC_CONFIG_HOME=$(mktemp -d)/ghsec
./dist/ghsec
#   -> onboarding appears, asks for a token, verifies with GET /user,
#      prints the config path, saves 0600

# 2. permissions
stat -f '%Sp' "$GHSEC_CONFIG_HOME/config.json"     # macOS: -rw-------
ls -l   "$GHSEC_CONFIG_HOME/config.json"           # Linux: -rw-------

# 3. profile management
#    menu -> Manage API keys / profiles -> add / switch / delete

# 4. wrong repo
#    menu -> Submit a private vulnerability report -> repo "nope/nope"
#    -> friendly 404 panel, no panic

# 5. interrupt
./dist/ghsec    # press Ctrl+C at the token prompt
echo $?         # 130, and no config file is created
```
