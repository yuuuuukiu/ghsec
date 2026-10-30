package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/yukiu/ghsec/internal/api"
)

// mockGitHub records requests and replies with a canned advisory.
type mockGitHub struct {
	mu       sync.Mutex
	requests []recordedCall
	status   int
	body     string
	server   *httptest.Server
}

type recordedCall struct {
	method string
	path   string
	header http.Header
	body   string
}

func newMockGitHub(t *testing.T) *mockGitHub {
	t.Helper()
	m := &mockGitHub{
		status: http.StatusCreated,
		body: `{"ghsa_id":"GHSA-test-0001","cve_id":"CVE-2026-9999","summary":"s",` +
			`"severity":"high","state":"triage","html_url":"https://example.test/a"}`,
	}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		m.mu.Lock()
		m.requests = append(m.requests, recordedCall{
			method: r.Method,
			path:   r.URL.Path,
			header: r.Header.Clone(),
			body:   string(raw),
		})
		status, body := m.status, m.body
		m.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockGitHub) calls() []recordedCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]recordedCall, len(m.requests))
	copy(out, m.requests)
	return out
}

// captureOutput runs fn with stdout/stderr redirected.
func captureOutput(t *testing.T, fn func()) (string, string) {
	t.Helper()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW

	var wg sync.WaitGroup
	var outBuf, errBuf bytes.Buffer
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(&outBuf, outR) }()
	go func() { defer wg.Done(); _, _ = io.Copy(&errBuf, errR) }()

	fn()

	os.Stdout, os.Stderr = oldOut, oldErr
	_ = outW.Close()
	_ = errW.Close()
	wg.Wait()
	_ = outR.Close()
	_ = errR.Close()
	return outBuf.String(), errBuf.String()
}

func TestParseFlagsRejectsUnknownAndExtra(t *testing.T) {
	fs := buildFlagSet("report")
	if err := parseFlags(fs, []string{"--nope"}); err == nil {
		t.Fatal("unknown flag must be a usage error")
	} else if !isUsageError(err) {
		t.Fatalf("error is not a usage error: %T", err)
	}

	fs2 := buildFlagSet("report")
	if err := parseFlags(fs2, []string{"stray"}); err == nil {
		t.Fatal("positional arguments must be rejected")
	}

	fs3 := buildFlagSet("report")
	if err := parseFlags(fs3, []string{"-h"}); !errors.Is(err, errFlagHandled) {
		t.Fatalf("-h should short-circuit, got %v", err)
	}
}

func TestValidateCVE(t *testing.T) {
	valid := []string{"", "  ", "CVE-2026-1234", "cve-2024-1234567"}
	for _, v := range valid {
		if err := validateCVE(v); err != nil {
			t.Fatalf("validateCVE(%q) = %v, want nil", v, err)
		}
	}
	invalid := []string{"GHSA-1234", "CVE-24-1234", "CVE-2026-123", "1234"}
	for _, v := range invalid {
		if err := validateCVE(v); err == nil {
			t.Fatalf("validateCVE(%q) = nil, want an error", v)
		}
	}
}

func TestWriteFlagsValidate(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		w := writeFlags{repo: "acme/widget", summary: "RCE", severity: "high", description: "details"}
		owner, repo, sev, desc, err := w.validate()
		if err != nil {
			t.Fatalf("validate() = %v", err)
		}
		if owner != "acme" || repo != "widget" || sev != api.SeverityHigh || desc != "details" {
			t.Fatalf("got %q %q %q %q", owner, repo, sev, desc)
		}
	})

	t.Run("demo default severity is medium", func(t *testing.T) {
		// The flag default must be medium, matching the spec's TUI default.
		fs := buildFlagSet("report")
		var w writeFlags
		w.register(fs, false)
		if err := fs.Parse([]string{}); err != nil {
			t.Fatal(err)
		}
		if w.severity != "medium" {
			t.Fatalf("default severity = %q, want medium", w.severity)
		}
	})

	bad := []struct {
		name string
		w    writeFlags
	}{
		{"missing repo", writeFlags{summary: "s", description: "d"}},
		{"bad repo", writeFlags{repo: "noslash", summary: "s", description: "d"}},
		{"missing summary", writeFlags{repo: "a/b", description: "d"}},
		{"long summary", writeFlags{repo: "a/b", summary: strings.Repeat("x", 257), description: "d"}},
		{"bad severity", writeFlags{repo: "a/b", summary: "s", severity: "severe", description: "d"}},
		{"missing description", writeFlags{repo: "a/b", summary: "s"}},
		{"both description sources", writeFlags{repo: "a/b", summary: "s", description: "d", descFile: "f"}},
		{"bad cve", writeFlags{repo: "a/b", summary: "s", description: "d", cve: "CVE-1"}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			w := tc.w
			w.severity = defaultIfEmpty(w.severity)
			if _, _, _, _, err := w.validate(); err == nil {
				t.Fatal("validate() must reject this input")
			} else if !isUsageError(err) {
				t.Fatalf("validate() error is not a usage error: %T (%v)", err, err)
			}
		})
	}
}

// defaultIfEmpty mirrors the flag default so the table above stays readable.
func defaultIfEmpty(s string) string {
	if s == "" {
		return "medium"
	}
	return s
}

func TestWriteFlagsDescriptionFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "advisory.md")
	if err := os.WriteFile(path, []byte("## Summary\n\nRCE details.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := writeFlags{repo: "a/b", summary: "s", severity: "low", descFile: path}
	_, _, _, desc, err := w.validate()
	if err != nil {
		t.Fatalf("validate() = %v", err)
	}
	if !strings.Contains(desc, "RCE details") {
		t.Fatalf("description = %q", desc)
	}

	w2 := writeFlags{repo: "a/b", summary: "s", severity: "low", descFile: filepath.Join(dir, "missing.md")}
	if _, _, _, _, err := w2.validate(); err == nil {
		t.Fatal("a missing description file must be an error")
	}
}

func TestClientFlagsResolvePrecedence(t *testing.T) {
	t.Setenv("GHSEC_CONFIG_HOME", t.TempDir())
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	t.Run("explicit flag wins", func(t *testing.T) {
		t.Setenv("GITHUB_TOKEN", "from-env")
		c := clientFlags{token: "from-flag"}
		client, source, err := c.resolve()
		if err != nil {
			t.Fatalf("resolve() = %v", err)
		}
		if !client.HasToken() {
			t.Fatal("client has no token")
		}
		if source != "--token flag" {
			t.Fatalf("source = %q", source)
		}
	})

	t.Run("GITHUB_TOKEN beats GH_TOKEN", func(t *testing.T) {
		t.Setenv("GITHUB_TOKEN", "primary")
		t.Setenv("GH_TOKEN", "secondary")
		_, source, err := (&clientFlags{}).resolve()
		if err != nil {
			t.Fatalf("resolve() = %v", err)
		}
		if source != "$GITHUB_TOKEN" {
			t.Fatalf("source = %q", source)
		}
	})

	t.Run("GH_TOKEN fallback", func(t *testing.T) {
		t.Setenv("GITHUB_TOKEN", "")
		t.Setenv("GH_TOKEN", "secondary")
		_, source, err := (&clientFlags{}).resolve()
		if err != nil {
			t.Fatalf("resolve() = %v", err)
		}
		if source != "$GH_TOKEN" {
			t.Fatalf("source = %q", source)
		}
	})

	t.Run("no credentials is a usage error", func(t *testing.T) {
		t.Setenv("GITHUB_TOKEN", "")
		t.Setenv("GH_TOKEN", "")
		_, _, err := (&clientFlags{}).resolve()
		if err == nil {
			t.Fatal("resolve() must fail without a token")
		}
		if !isUsageError(err) {
			t.Fatalf("error is not a usage error: %T", err)
		}
		if !strings.Contains(err.Error(), "GITHUB_TOKEN") {
			t.Fatalf("error should mention the env var: %v", err)
		}
	})

	t.Run("token and profile are mutually exclusive", func(t *testing.T) {
		_, _, err := (&clientFlags{token: "t", profile: "p"}).resolve()
		if err == nil || !isUsageError(err) {
			t.Fatalf("expected a usage error, got %v", err)
		}
	})

	t.Run("unknown profile names the available ones", func(t *testing.T) {
		t.Setenv("GITHUB_TOKEN", "")
		t.Setenv("GH_TOKEN", "")
		dir := t.TempDir()
		t.Setenv("GHSEC_CONFIG_HOME", dir)
		seedProfile(t, "work", "ghp_seed0000000000000000")
		_, _, err := (&clientFlags{profile: "nope"}).resolve()
		if err == nil || !strings.Contains(err.Error(), "work") {
			t.Fatalf("error should list available profiles: %v", err)
		}
	})

	t.Run("stored profile is used", func(t *testing.T) {
		t.Setenv("GITHUB_TOKEN", "")
		t.Setenv("GH_TOKEN", "")
		dir := t.TempDir()
		t.Setenv("GHSEC_CONFIG_HOME", dir)
		seedProfile(t, "stored", "ghp_stored00000000000000")
		client, source, err := (&clientFlags{}).resolve()
		if err != nil {
			t.Fatalf("resolve() = %v", err)
		}
		if !client.HasToken() {
			t.Fatal("client has no token")
		}
		if source != "profile stored" {
			t.Fatalf("source = %q", source)
		}
	})
}

// seedProfile writes a config containing one profile via the CLI itself.
func seedProfile(t *testing.T, alias, token string) {
	t.Helper()
	args := []string{"add", "--alias", alias, "--token", token, "--no-verify"}
	if err := runProfileCmd(context.Background(), args); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
}

func TestConfirmSubmitRequiresYesWhenNotATerminal(t *testing.T) {
	// The test process is not attached to a terminal, so confirmation must be
	// refused unless autoYes is set. This is the guard that prevents a piped
	// invocation from silently filing a report.
	if ok, err := confirmSubmit(false, "sure?"); err == nil || ok {
		t.Fatalf("confirmSubmit(false) = %v, %v; want a usage error", ok, err)
	} else if !isUsageError(err) || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("error should demand --yes, got %v", err)
	}
	if ok, err := confirmSubmit(true, "sure?"); err != nil || !ok {
		t.Fatalf("confirmSubmit(true) = %v, %v", ok, err)
	}
}

func TestRunReportCmdDryRunDoesNotCallNetwork(t *testing.T) {
	t.Setenv("GHSEC_CONFIG_HOME", t.TempDir())
	mock := newMockGitHub(t)

	out, _ := captureOutput(t, func() {
		err := runReportCmd(context.Background(), []string{
			"--repo", "acme/widget", "--summary", "RCE", "--severity", "critical",
			"--description", "body", "--dry-run", "--yes",
			"--api-url", mock.server.URL,
		})
		if err != nil {
			t.Errorf("dry run failed: %v", err)
		}
	})
	if !strings.Contains(out, "dry run") {
		t.Fatalf("output = %q", out)
	}
	if len(mock.calls()) != 0 {
		t.Fatalf("--dry-run must not call GitHub, got %d calls", len(mock.calls()))
	}
}

func TestRunReportCmdSubmits(t *testing.T) {
	t.Setenv("GHSEC_CONFIG_HOME", t.TempDir())
	mock := newMockGitHub(t)

	out, errOut := captureOutput(t, func() {
		err := runReportCmd(context.Background(), []string{
			"--repo", "acme/widget", "--summary", "RCE in loader", "--severity", "high",
			"--cve", "cve-2026-1234", "--description", "full details",
			"--token", "ghp_cli0123456789abcdefghij", "--yes",
			"--api-url", mock.server.URL,
		})
		if err != nil {
			t.Errorf("runReportCmd() = %v", err)
		}
	})

	calls := mock.calls()
	if len(calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(calls))
	}
	call := calls[0]
	if call.method != http.MethodPost {
		t.Fatalf("method = %q", call.method)
	}
	if want := "/repos/acme/widget/security-advisories/reports"; call.path != want {
		t.Fatalf("path = %q, want %q", call.path, want)
	}
	if got := call.header.Get("Authorization"); got != "Bearer ghp_cli0123456789abcdefghij" {
		t.Fatalf("Authorization = %q", got)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(call.body), &payload); err != nil {
		t.Fatalf("payload is not JSON: %v (%q)", err, call.body)
	}
	if payload["summary"] != "RCE in loader" {
		t.Fatalf("summary = %v", payload["summary"])
	}
	if payload["severity"] != "high" {
		t.Fatalf("severity = %v", payload["severity"])
	}
	if payload["cve_id"] != "CVE-2026-1234" {
		t.Fatalf("cve_id = %v, want it upper-cased", payload["cve_id"])
	}
	if !strings.Contains(out, "GHSA-test-0001") {
		t.Fatalf("stdout should carry the advisory id: %q", out)
	}
	if !strings.Contains(errOut, "authenticated with") {
		t.Fatalf("stderr should note the credential source: %q", errOut)
	}
}

func TestRunReportCmdJSONOutput(t *testing.T) {
	t.Setenv("GHSEC_CONFIG_HOME", t.TempDir())
	mock := newMockGitHub(t)

	out, _ := captureOutput(t, func() {
		err := runReportCmd(context.Background(), []string{
			"--repo", "acme/widget", "--summary", "s", "--severity", "low",
			"--description", "d", "--token", "ghp_x0123456789abcdefghij", "--yes", "--json",
			"--api-url", mock.server.URL,
		})
		if err != nil {
			t.Errorf("runReportCmd() = %v", err)
		}
	})

	var got result
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%q", err, out)
	}
	if !got.OK || got.GHSAID != "GHSA-test-0001" || got.Repository != "acme/widget" {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestRunReportCmdRefusesWithoutYes(t *testing.T) {
	t.Setenv("GHSEC_CONFIG_HOME", t.TempDir())
	mock := newMockGitHub(t)

	_, _ = captureOutput(t, func() {
		err := runReportCmd(context.Background(), []string{
			"--repo", "acme/widget", "--summary", "s", "--severity", "medium",
			"--description", "d", "--token", "ghp_x0123456789abcdefghij",
			"--api-url", mock.server.URL,
		})
		if err == nil {
			t.Error("runReportCmd must refuse without --yes when not attached to a terminal")
		}
	})
	if len(mock.calls()) != 0 {
		t.Fatalf("nothing should be submitted, got %d calls", len(mock.calls()))
	}
}

func TestRunAdvisoryCmdSendsAffectedSection(t *testing.T) {
	t.Setenv("GHSEC_CONFIG_HOME", t.TempDir())
	mock := newMockGitHub(t)

	captureOutput(t, func() {
		err := runAdvisoryCmd(context.Background(), []string{
			"--repo", "acme/widget", "--summary", "YAML RCE", "--severity", "critical",
			"--description", "body", "--affected", "<= 1.4.2", "--yes",
			"--token", "ghp_x0123456789abcdefghij", "--api-url", mock.server.URL,
		})
		if err != nil {
			t.Errorf("runAdvisoryCmd() = %v", err)
		}
	})

	calls := mock.calls()
	if len(calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(calls))
	}
	if want := "/repos/acme/widget/security-advisories"; calls[0].path != want {
		t.Fatalf("path = %q, want %q", calls[0].path, want)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(calls[0].body), &payload); err != nil {
		t.Fatalf("payload: %v", err)
	}
	desc, _ := payload["description"].(string)
	if !strings.Contains(desc, "Affected versions") || !strings.Contains(desc, "1.4.2") {
		t.Fatalf("description should contain the affected section: %q", desc)
	}
}

func TestRunReportCmdSurfacesAPIFailure(t *testing.T) {
	t.Setenv("GHSEC_CONFIG_HOME", t.TempDir())
	mock := newMockGitHub(t)
	mock.status = http.StatusForbidden
	mock.body = `{"message":"Resource not accessible by integration"}`

	var gotErr error
	captureOutput(t, func() {
		gotErr = runReportCmd(context.Background(), []string{
			"--repo", "acme/widget", "--summary", "s", "--severity", "low",
			"--description", "d", "--token", "ghp_x0123456789abcdefghij", "--yes",
			"--api-url", mock.server.URL,
		})
	})
	if gotErr == nil {
		t.Fatal("a 403 must fail the command")
	}
	if !strings.Contains(gotErr.Error(), "private vulnerability reporting") {
		t.Fatalf("error should carry the actionable 403 guidance, got: %v", gotErr)
	}
	if strings.Contains(gotErr.Error(), "goroutine") {
		t.Fatalf("error leaked internals: %v", gotErr)
	}
}

func TestProfileSubcommands(t *testing.T) {
	t.Setenv("GHSEC_CONFIG_HOME", t.TempDir())

	out, _ := captureOutput(t, func() {
		if err := runProfileCmd(context.Background(), []string{"list"}); err != nil {
			t.Errorf("list on an empty config = %v", err)
		}
	})
	if !strings.Contains(strings.ToLower(out), "no profiles") {
		t.Fatalf("empty list output = %q", out)
	}

	captureOutput(t, func() {
		if err := runProfileCmd(context.Background(), []string{
			"add", "--alias", "work", "--token", "ghp_list0000000000000000", "--no-verify",
		}); err != nil {
			t.Errorf("add = %v", err)
		}
	})

	out, _ = captureOutput(t, func() {
		if err := runProfileCmd(context.Background(), []string{"list"}); err != nil {
			t.Errorf("list = %v", err)
		}
	})
	if !strings.Contains(out, "work") || !strings.Contains(out, "ghp_****") {
		t.Fatalf("list output = %q", out)
	}
	if strings.Contains(out, "0000000000") {
		t.Fatalf("list leaked the token: %q", out)
	}

	// Adding a second profile lets us switch and remove safely.
	captureOutput(t, func() {
		_ = runProfileCmd(context.Background(), []string{
			"add", "--alias", "personal", "--token", "ghp_two00000000000000000", "--no-verify",
		})
	})
	captureOutput(t, func() {
		if err := runProfileCmd(context.Background(), []string{"use", "work"}); err != nil {
			t.Errorf("use = %v", err)
		}
	})
	captureOutput(t, func() {
		if err := runProfileCmd(context.Background(), []string{"remove", "personal"}); err != nil {
			t.Errorf("remove = %v", err)
		}
	})
	captureOutput(t, func() {
		if err := runProfileCmd(context.Background(), []string{"remove", "work"}); err == nil {
			t.Error("removing the last profile must fail")
		}
	})
}

func TestRunProfileCmdUsageErrors(t *testing.T) {
	t.Setenv("GHSEC_CONFIG_HOME", t.TempDir())
	cases := [][]string{
		{},
		{"bogus"},
		{"use"},
		{"use", "a", "b"},
		{"remove"},
	}
	for _, args := range cases {
		_, _ = captureOutput(t, func() {
			if err := runProfileCmd(context.Background(), args); err == nil {
				t.Errorf("runProfileCmd(%v) = nil, want an error", args)
			} else if !isUsageError(err) {
				t.Errorf("runProfileCmd(%v) error is not a usage error: %T", args, err)
			}
		})
	}
}

func TestEmitFormats(t *testing.T) {
	r := result{OK: true, Repository: "a/b", ID: "GHSA-1", GHSAID: "GHSA-1",
		Summary: "s", Severity: "high", State: "triage", URL: "https://x"}

	var buf bytes.Buffer
	if err := emit(&buf, r, false); err != nil {
		t.Fatalf("emit text = %v", err)
	}
	for _, want := range []string{"GHSA-1", "a/b", "high", "triage", "https://x"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("text output missing %q: %q", want, buf.String())
		}
	}

	buf.Reset()
	if err := emit(&buf, r, true); err != nil {
		t.Fatalf("emit json = %v", err)
	}
	var decoded result
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("json output invalid: %v", err)
	}
	if decoded.GHSAID != "GHSA-1" {
		t.Fatalf("decoded = %+v", decoded)
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "  ", "b", "c"); got != "b" {
		t.Fatalf("firstNonEmpty() = %q", got)
	}
	if got := firstNonEmpty("", " "); got != "" {
		t.Fatalf("firstNonEmpty() = %q, want empty", got)
	}
}
