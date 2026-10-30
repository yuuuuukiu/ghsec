package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/yukiu/ghsec/internal/api"
	"github.com/yukiu/ghsec/internal/config"
	"github.com/yukiu/ghsec/internal/tui"
)

func TestOwnerOfAndRepoOf(t *testing.T) {
	cases := []struct {
		spec, wantOwner, wantRepo string
	}{
		{"octocat/Hello-World", "octocat", "Hello-World"},
		{"a/b", "a", "b"},
		{"my.org/my_repo-1", "my.org", "my_repo-1"},
		// Degenerate inputs must not panic or truncate incorrectly.
		{"noslash", "noslash", ""},
		{"", "", ""},
		{"/repo", "/repo", ""},
		{"owner/", "owner", ""},
	}
	for _, tc := range cases {
		if got := ownerOf(tc.spec); got != tc.wantOwner {
			t.Fatalf("ownerOf(%q) = %q, want %q", tc.spec, got, tc.wantOwner)
		}
		if got := repoOf(tc.spec); got != tc.wantRepo {
			t.Fatalf("repoOf(%q) = %q, want %q", tc.spec, got, tc.wantRepo)
		}
	}
}

func TestHandleFlags(t *testing.T) {
	if err := handleFlags(nil); err != nil {
		t.Fatalf("handleFlags(nil) = %v, want nil", err)
	}
	for _, arg := range []string{"--help", "-h", "help", "--version", "-v", "version"} {
		if err := handleFlags([]string{arg}); !errors.Is(err, errFlagHandled) {
			t.Fatalf("handleFlags(%q) = %v, want errFlagHandled", arg, err)
		}
	}
	err := handleFlags([]string{"--nope"})
	if err == nil || errors.Is(err, errFlagHandled) {
		t.Fatalf("handleFlags(--nope) = %v, want a real error", err)
	}
	if !strings.Contains(err.Error(), "unknown argument") {
		t.Fatalf("unknown flag error = %q", err.Error())
	}
}

// captureStdout runs fn with os.Stdout redirected and returns what it wrote.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	defer func() {
		os.Stdout = old
		_ = r.Close()
	}()

	fn()
	_ = w.Close()
	return <-done
}

func TestLoadConfigFirstRunIsNotAnError(t *testing.T) {
	t.Setenv("GHSEC_CONFIG_HOME", t.TempDir())
	a := &app{}
	if err := a.loadConfig(); err != nil {
		t.Fatalf("loadConfig() = %v, want nil on first run", err)
	}
	if a.cfg == nil || !a.cfg.IsEmpty() {
		t.Fatal("first run must produce an empty, initialised config")
	}
	if a.cfgErr != nil {
		t.Fatalf("cfgErr = %v, want nil", a.cfgErr)
	}
}

func TestLoadConfigCorruptIsRecordedNotFatal(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GHSEC_CONFIG_HOME", dir)
	if err := os.WriteFile(dir+"/config.json", []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &app{}
	if err := a.loadConfig(); err != nil {
		t.Fatalf("loadConfig() must not fail on a corrupt file, got %v", err)
	}
	if a.cfgErr == nil {
		t.Fatal("cfgErr must record the parse failure so the UI can warn")
	}
	if a.cfg == nil || !a.cfg.IsEmpty() {
		t.Fatal("a corrupt file must degrade to an empty config")
	}
}

func TestProfileTableMasksTokensAndMarksActive(t *testing.T) {
	a := &app{cfg: &config.Config{
		ActiveProfile: "work",
		Profiles: map[string]config.Profile{
			"work":     {Token: "ghp_secretMiddle1234", Username: "octocat"},
			"personal": {Token: "ghp_otherSecret5678", Username: "mona"},
		},
	}}
	out := a.profileTable()
	if strings.Contains(out, "secretMiddle") || strings.Contains(out, "otherSecret") {
		t.Fatalf("profileTable leaked a token:\n%s", out)
	}
	for _, want := range []string{"work", "personal", "octocat", "mona", "****1234", "****5678"} {
		if !strings.Contains(out, want) {
			t.Fatalf("profileTable() missing %q:\n%s", want, out)
		}
	}
}

func TestProfileTableEmpty(t *testing.T) {
	a := &app{cfg: &config.Config{Profiles: map[string]config.Profile{}}}
	if out := a.profileTable(); !strings.Contains(strings.ToLower(out), "no profiles") {
		t.Fatalf("empty profileTable() = %q", out)
	}
}

func TestMustPathNeverEmpty(t *testing.T) {
	t.Setenv("GHSEC_CONFIG_HOME", t.TempDir())
	if got := mustPath(); got == "" {
		t.Fatal("mustPath() must never return an empty string")
	}
}

func TestVerifyTokenFailureIsFriendly(t *testing.T) {
	// Point at an unroutable port so the call fails fast without a network.
	t.Setenv("GITHUB_API_URL", "http://127.0.0.1:9")
	a := &app{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var profile config.Profile
	var err error
	out := captureStdout(t, func() {
		profile, err = a.verifyToken(ctx, "ghp_0123456789abcdefghij")
	})
	if err == nil {
		t.Fatal("verifyToken() must fail when GitHub is unreachable")
	}
	if profile.Token != "" {
		t.Fatal("verifyToken() must not return a profile on failure")
	}
	if strings.Contains(err.Error(), "{") || strings.Contains(err.Error(), "goroutine") {
		t.Fatalf("verifyToken() leaked internals: %v", err)
	}
	if !strings.Contains(strings.ToLower(out), "verifying") {
		t.Fatalf("verifyToken() should tell the user what is happening, got %q", out)
	}
}

func TestReportFlowErrSwallowsAbort(t *testing.T) {
	a := &app{}
	out := captureStdout(t, func() {
		a.reportFlowErr("report", tui.ErrAborted)
	})
	if !strings.Contains(strings.ToLower(out), "cancelled") {
		t.Fatalf("abort should print a cancellation notice, got %q", out)
	}

	out = captureStdout(t, func() {
		a.reportFlowErr("report", errors.New("boom"))
	})
	if !strings.Contains(out, "boom") {
		t.Fatalf("real errors must be surfaced, got %q", out)
	}
}

// TestFriendlyMessagesCoverSpecErrorCodes pins the acceptance criterion that
// 403/404 map to guidance rather than raw JSON.
func TestFriendlyMessagesCoverSpecErrorCodes(t *testing.T) {
	forbidden := api.FriendlyMessage(&api.APIError{StatusCode: 403}, "submit the report")
	if !strings.Contains(forbidden, "private vulnerability reporting") {
		t.Fatalf("403 guidance = %q", forbidden)
	}
	notFound := api.FriendlyMessage(&api.APIError{StatusCode: 404}, "submit the report")
	if !strings.Contains(notFound, "not found") {
		t.Fatalf("404 guidance = %q", notFound)
	}
}

func TestWarnIfReportingDisabledIsSilentOnBadSpec(t *testing.T) {
	a := &app{} // nil client: the function must return without panicking
	out := captureStdout(t, func() {
		a.warnIfReportingDisabled(context.Background(), "not-a-spec")
	})
	if out != "" {
		t.Fatalf("warnIfReportingDisabled() should stay silent for a malformed spec, got %q", out)
	}
}
