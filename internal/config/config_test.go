package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func withTempHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(configHomeEnv, dir)
	return dir
}

func TestDirHonoursOverrideAndXDG(t *testing.T) {
	dir := withTempHome(t)
	got, err := Dir()
	if err != nil {
		t.Fatalf("Dir() error = %v", err)
	}
	if got != dir {
		t.Fatalf("Dir() = %q, want %q", got, dir)
	}

	if runtime.GOOS == "windows" {
		// Dir() resolves %APPDATA% on Windows and deliberately ignores the Unix
		// XDG_CONFIG_HOME convention, so there is nothing to assert here.
		return
	}

	t.Setenv(configHomeEnv, "")
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	got, err = Dir()
	if err != nil {
		t.Fatalf("Dir() error = %v", err)
	}
	if want := filepath.Join(xdg, "ghsec"); got != want {
		t.Fatalf("Dir() = %q, want %q", got, want)
	}
}

func TestPathUsesConfigFileName(t *testing.T) {
	withTempHome(t)
	path, err := Path()
	if err != nil {
		t.Fatalf("Path() error = %v", err)
	}
	if filepath.Base(path) != ConfigFileName {
		t.Fatalf("Path() base = %q, want %q", filepath.Base(path), ConfigFileName)
	}
}

func TestLoadMissingFileReturnsErrNoConfig(t *testing.T) {
	withTempHome(t)
	cfg, err := Load()
	if !errors.Is(err, ErrNoConfig) {
		t.Fatalf("Load() error = %v, want ErrNoConfig", err)
	}
	if cfg == nil || cfg.Profiles == nil {
		t.Fatal("Load() must return an initialised config alongside ErrNoConfig")
	}
	if !cfg.IsEmpty() {
		t.Fatal("first run config must be empty")
	}
}

func TestLoadEmptyFileReturnsErrNoConfig(t *testing.T) {
	dir := withTempHome(t)
	path := filepath.Join(dir, ConfigFileName)
	if err := os.WriteFile(path, []byte("  \n"), FileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); !errors.Is(err, ErrNoConfig) {
		t.Fatalf("Load() error = %v, want ErrNoConfig", err)
	}
}

func TestLoadMalformedFileErrors(t *testing.T) {
	dir := withTempHome(t)
	path := filepath.Join(dir, ConfigFileName)
	if err := os.WriteFile(path, []byte("{not json"), FileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("Load() must fail on malformed JSON")
	}
}

func TestSaveLoadRoundTripAndPermissions(t *testing.T) {
	dir := withTempHome(t)
	cfg := newConfig()
	if err := cfg.AddProfile("work", Profile{Token: "ghp_abcdefgh1234", Username: "octocat"}); err != nil {
		t.Fatalf("AddProfile() error = %v", err)
	}
	if err := cfg.AddProfile("personal", Profile{Token: "ghp_zzzzzzzz9999", Username: "mona"}); err != nil {
		t.Fatalf("AddProfile() error = %v", err)
	}
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	path, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	// Windows has no POSIX permission bits; os.Stat always reports 0666 there,
	// so the 0600 contract is only meaningful (and only enforced) on Unix.
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != FileMode {
			t.Fatalf("config permissions = %o, want %o", perm, FileMode)
		}
		dirInfo, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if perm := dirInfo.Mode().Perm(); perm != DirMode {
			t.Fatalf("config dir permissions = %o, want %o", perm, DirMode)
		}
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded.ActiveProfile != "work" {
		t.Fatalf("ActiveProfile = %q, want work", loaded.ActiveProfile)
	}
	if got := loaded.Profiles["personal"].Username; got != "mona" {
		t.Fatalf("personal username = %q, want mona", got)
	}
	if len(loaded.Profiles) != 2 {
		t.Fatalf("profile count = %d, want 2", len(loaded.Profiles))
	}
}

func TestSaveLeavesNoTempFiles(t *testing.T) {
	dir := withTempHome(t)
	cfg := newConfig()
	if err := cfg.AddProfile("a", Profile{Token: "t", Username: "u"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := cfg.Save(); err != nil {
			t.Fatalf("Save() #%d error = %v", i, err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("stale temp file left behind: %s", e.Name())
		}
	}
	if len(entries) != 1 {
		t.Fatalf("config dir entries = %d, want 1", len(entries))
	}
}

func TestNormalizeRecoversDanglingActiveProfile(t *testing.T) {
	dir := withTempHome(t)
	path := filepath.Join(dir, ConfigFileName)
	body := `{"active_profile":"ghost","profiles":{"keep":{"token":"t","username":"u"}}}`
	if err := os.WriteFile(path, []byte(body), FileMode); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.ActiveProfile != "keep" {
		t.Fatalf("ActiveProfile = %q, want keep", cfg.ActiveProfile)
	}
}

func TestSetActiveAndActive(t *testing.T) {
	cfg := newConfig()
	for _, alias := range []string{"b", "a"} {
		if err := cfg.AddProfile(alias, Profile{Token: "t" + alias, Username: alias}); err != nil {
			t.Fatal(err)
		}
	}
	// First added profile becomes active.
	if alias, _, ok := cfg.Active(); !ok || alias != "b" {
		t.Fatalf("Active() = %q,%v want b,true", alias, ok)
	}
	if err := cfg.SetActive("a"); err != nil {
		t.Fatalf("SetActive() error = %v", err)
	}
	alias, p, ok := cfg.Active()
	if !ok || alias != "a" || p.Token != "ta" {
		t.Fatalf("Active() = %q,%+v,%v", alias, p, ok)
	}
	if err := cfg.SetActive("nope"); err == nil {
		t.Fatal("SetActive() must reject unknown alias")
	}
}

func TestRemoveProfileGuards(t *testing.T) {
	cfg := newConfig()
	if err := cfg.AddProfile("only", Profile{Token: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := cfg.RemoveProfile("only"); err == nil {
		t.Fatal("removing the only profile must fail")
	}
	if err := cfg.AddProfile("second", Profile{Token: "t2"}); err != nil {
		t.Fatal(err)
	}
	if err := cfg.RemoveProfile("only"); err != nil {
		t.Fatalf("RemoveProfile() error = %v", err)
	}
	if cfg.ActiveProfile != "second" {
		t.Fatalf("ActiveProfile = %q, want second", cfg.ActiveProfile)
	}
	if err := cfg.RemoveProfile("missing"); err == nil {
		t.Fatal("removing an unknown profile must fail")
	}
}

func TestAliasesSorted(t *testing.T) {
	cfg := newConfig()
	for _, a := range []string{"zeta", "alpha", "mike"} {
		if err := cfg.AddProfile(a, Profile{Token: "t"}); err != nil {
			t.Fatal(err)
		}
	}
	got := cfg.Aliases()
	want := []string{"alpha", "mike", "zeta"}
	if len(got) != len(want) {
		t.Fatalf("Aliases() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Aliases() = %v, want %v", got, want)
		}
	}
}

func TestValidateAlias(t *testing.T) {
	valid := []string{"work", "Work_2024", "a", "a.b-c_d", strings.Repeat("a", 32)}
	for _, a := range valid {
		if err := ValidateAlias(a); err != nil {
			t.Fatalf("ValidateAlias(%q) = %v, want nil", a, err)
		}
	}
	invalid := []string{"", " ", "-lead", ".lead", "has space", "a/b", strings.Repeat("a", 33), "über"}
	for _, a := range invalid {
		if err := ValidateAlias(a); err == nil {
			t.Fatalf("ValidateAlias(%q) = nil, want error", a)
		}
	}
}

func TestAddProfileRejectsEmptyToken(t *testing.T) {
	cfg := newConfig()
	if err := cfg.AddProfile("a", Profile{Token: "   "}); err == nil {
		t.Fatal("AddProfile() must reject an empty token")
	}
}

func TestMaskToken(t *testing.T) {
	cases := map[string]string{
		"":                     "(none)",
		"   ":                  "(none)",
		"ghp_abcdEFGH1234":     "ghp_****1234",
		"github_pat_11ABCDEFG": "github_pat_****DEFG",
		"abcdefgh":             "****efgh",
		"abc":                  "****",
		"a":                    "****",
		"ghp_1":                "ghp_****",
	}
	for in, want := range cases {
		if got := MaskToken(in); got != want {
			t.Fatalf("MaskToken(%q) = %q, want %q", in, got, want)
		}
	}
	// The mask must never contain the middle of the token.
	token := "ghp_superSecretMiddleValue9999"
	if strings.Contains(MaskToken(token), "SecretMiddle") {
		t.Fatalf("MaskToken leaked token body: %q", MaskToken(token))
	}
}

func TestSaveToRejectsNil(t *testing.T) {
	var cfg *Config
	if err := cfg.SaveTo(filepath.Join(t.TempDir(), "c.json")); err == nil {
		t.Fatal("SaveTo() must reject a nil config")
	}
}

func TestLoadFromDirectoryErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadFrom(dir); err == nil {
		t.Fatal("LoadFrom() must reject a directory path")
	}
}

func TestAddSubmissionPrependsAndDedupes(t *testing.T) {
	cfg := newConfig()

	cfg.AddSubmission(Submission{Kind: KindReport, Owner: "a", Repo: "b", GHSAID: "GHSA-1", Summary: "first"})
	cfg.AddSubmission(Submission{Kind: KindAdvisory, Owner: "a", Repo: "b", GHSAID: "GHSA-2", Summary: "second"})
	if got := len(cfg.History); got != 2 {
		t.Fatalf("history length = %d, want 2", got)
	}
	// Newest first.
	if cfg.History[0].GHSAID != "GHSA-2" {
		t.Fatalf("history[0] = %q, want GHSA-2", cfg.History[0].GHSAID)
	}
	if cfg.History[0].SubmittedAt.IsZero() {
		t.Fatal("SubmittedAt must be filled in automatically")
	}

	// Re-adding the same GHSA in the same repo replaces, not duplicates.
	cfg.AddSubmission(Submission{Kind: KindAdvisory, Owner: "a", Repo: "b", GHSAID: "GHSA-2", Summary: "updated"})
	if got := len(cfg.History); got != 2 {
		t.Fatalf("history length after dedupe = %d, want 2", got)
	}
	if cfg.History[0].Summary != "updated" {
		t.Fatalf("dedupe kept the stale entry: %q", cfg.History[0].Summary)
	}

	// The same GHSA in a different repo is a different submission.
	cfg.AddSubmission(Submission{Kind: KindAdvisory, Owner: "x", Repo: "y", GHSAID: "GHSA-2"})
	if got := len(cfg.History); got != 3 {
		t.Fatalf("history length = %d, want 3", got)
	}
}

func TestAddSubmissionWithoutGHSAIsAlwaysKept(t *testing.T) {
	cfg := newConfig()
	for i := 0; i < 3; i++ {
		cfg.AddSubmission(Submission{Kind: KindReport, Owner: "a", Repo: "b", Summary: "no id yet"})
	}
	if got := len(cfg.History); got != 3 {
		t.Fatalf("history length = %d, want 3 (entries without an id cannot be deduped)", got)
	}
}

func TestHistoryIsCapped(t *testing.T) {
	cfg := newConfig()
	for i := 0; i < maxHistoryEntries+25; i++ {
		cfg.AddSubmission(Submission{Kind: KindReport, Owner: "a", Repo: "b", Summary: "s"})
	}
	if got := len(cfg.History); got != maxHistoryEntries {
		t.Fatalf("history length = %d, want the cap %d", got, maxHistoryEntries)
	}
}

func TestHistorySurvivesRoundTrip(t *testing.T) {
	dir := withTempHome(t)
	_ = dir
	cfg := newConfig()
	if err := cfg.AddProfile("work", Profile{Token: "ghp_abcdefgh1234", Username: "octocat"}); err != nil {
		t.Fatal(err)
	}
	cfg.AddSubmission(Submission{
		Kind: KindReport, Owner: "acme", Repo: "widget",
		GHSAID: "GHSA-1234-5678-9012", CVEID: "CVE-2026-1111",
		Summary: "RCE", Severity: "high", URL: "https://x", Alias: "work",
	})
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save() = %v", err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if len(loaded.History) != 1 {
		t.Fatalf("history length = %d, want 1", len(loaded.History))
	}
	got := loaded.History[0]
	if got.GHSAID != "GHSA-1234-5678-9012" || got.RepoSpec() != "acme/widget" || got.Kind != KindReport {
		t.Fatalf("round-tripped submission = %+v", got)
	}
}

func TestConfigWithoutHistoryStillLoads(t *testing.T) {
	dir := withTempHome(t)
	path := filepath.Join(dir, ConfigFileName)
	body := `{"active_profile":"w","profiles":{"w":{"token":"t","username":"u"}}}`
	if err := os.WriteFile(path, []byte(body), FileMode); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if len(cfg.History) != 0 {
		t.Fatalf("history should be empty for an old config, got %d", len(cfg.History))
	}
}

func TestSubmissionRepoSpecAndClear(t *testing.T) {
	if got := (Submission{}).RepoSpec(); got != "" {
		t.Fatalf("RepoSpec() = %q, want empty", got)
	}
	cfg := newConfig()
	cfg.AddSubmission(Submission{Owner: "a", Repo: "b"})
	cfg.ClearHistory()
	if len(cfg.Submissions()) != 0 {
		t.Fatal("ClearHistory() did not clear")
	}
}
