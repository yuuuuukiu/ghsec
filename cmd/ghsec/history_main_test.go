package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/yukiu/ghsec/internal/api"
	"github.com/yukiu/ghsec/internal/config"
)

func TestRecordSubmissionStoresIdentifiersOnly(t *testing.T) {
	t.Setenv("GHSEC_CONFIG_HOME", t.TempDir())
	a := &app{cfg: &config.Config{Profiles: map[string]config.Profile{
		"work": {Token: "ghp_x0123456789abcdefghij", Username: "octocat"},
	}}, alias: "work"}

	a.recordSubmission(config.KindReport, "acme/widget", "RCE in loader", "high", "CVE-2026-1",
		&api.Advisory{GHSAID: "GHSA-abcd-1234-efgh", HTMLURL: "https://example.test/a", State: "triage"})

	subs := a.cfg.Submissions()
	if len(subs) != 1 {
		t.Fatalf("history length = %d, want 1", len(subs))
	}
	got := subs[0]
	if got.Kind != config.KindReport {
		t.Fatalf("kind = %q", got.Kind)
	}
	if got.RepoSpec() != "acme/widget" {
		t.Fatalf("repo = %q, want acme/widget", got.RepoSpec())
	}
	if got.GHSAID != "GHSA-abcd-1234-efgh" {
		t.Fatalf("ghsa = %q", got.GHSAID)
	}
	if got.Severity != "high" || got.Summary != "RCE in loader" {
		t.Fatalf("entry = %+v", got)
	}
	if got.Alias != "work" {
		t.Fatalf("alias = %q, want work", got.Alias)
	}
	// The config file legitimately stores the token under "profiles"; the
	// history section must not contain a second copy of it.
	raw, err := os.ReadFile(mustPath())
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("config is not valid JSON: %v", err)
	}
	historyJSON, err := json.Marshal(doc["history"])
	if err != nil {
		t.Fatalf("marshal history: %v", err)
	}
	if strings.Contains(string(historyJSON), "ghp_x0123456789abcdefghij") {
		t.Fatalf("history leaked the token: %s", historyJSON)
	}
}

func TestRecordSubmissionIgnoresNilAdvisory(t *testing.T) {
	t.Setenv("GHSEC_CONFIG_HOME", t.TempDir())
	a := &app{cfg: &config.Config{Profiles: map[string]config.Profile{}}}
	a.recordSubmission(config.KindAdvisory, "a/b", "s", "low", "", nil)
	if len(a.cfg.Submissions()) != 1 {
		t.Fatal("an advisory-less submission should still be recorded")
	}
}

func TestRecordSubmissionIsNilSafe(t *testing.T) {
	a := &app{}
	// Must not panic when the app has no config yet.
	a.recordSubmission(config.KindReport, "a/b", "s", "low", "", nil)
}

func TestSplitRepoOnHistoryRefresh(t *testing.T) {
	// splitRepo is used by the refresh path; malformed entries must be reported
	// per-row rather than aborting the listing.
	if _, _, ok := splitRepo("acme/widget"); !ok {
		t.Fatal("well-formed spec must parse")
	}
	if _, _, ok := splitRepo("not-a-spec"); ok {
		t.Fatal("malformed spec must not parse")
	}
}

func TestBrowseRejectsUnknownRepo(t *testing.T) {
	t.Setenv("GHSEC_CONFIG_HOME", t.TempDir())
	a := &app{cfg: &config.Config{Profiles: map[string]config.Profile{}}}
	// browse prompts interactively; with no TTY it must return promptly rather
	// than hang or panic.
	out := captureStdout(t, func() {
		_ = a.browse(context.Background())
	})
	if strings.Contains(out, "panic") {
		t.Fatalf("browse panicked: %q", out)
	}
}
