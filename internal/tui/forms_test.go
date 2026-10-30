package tui

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/charmbracelet/huh"

	"github.com/yuuuuukiu/ghsec/internal/api"
)

func TestValidateRepoSpecValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		spec string
	}{
		{"octocat/Hello-World"},
		{"a/b"},
		{"my.org/my_repo-1"},
		{"OCTOCAT/hello.world"},
		{"owner/1234567890"},
		{strings.Repeat("a", 39) + "/b"},
		{"a/" + strings.Repeat("b", 100)},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.spec, func(t *testing.T) {
			t.Parallel()
			if err := validateRepoSpec(tt.spec); err != nil {
				t.Fatalf("validateRepoSpec(%q) = %v, want nil", tt.spec, err)
			}
		})
	}
}

func TestValidateRepoSpecInvalid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		spec string
	}{
		{"empty", ""},
		{"blank", "   "},
		{"no slash", "noslash"},
		{"two slashes", "a/b/c"},
		{"leading slash", "/b"},
		{"trailing slash", "a/"},
		{"space in owner", "a b/c"},
		{"space in repo", "a/b c"},
		{"leading space", " a/b"},
		{"trailing space", "a/b "},
		{"owner too long", strings.Repeat("a", 40) + "/b"},
		{"repo too long", "a/" + strings.Repeat("b", 101)},
		{"owner starts with dash", "-a/b"},
		{"owner starts with dot", ".a/b"},
		{"repo invalid char", "a/b$c"},
		{"newline", "a/b\n"},
		{"tab", "a\t/b"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateRepoSpec(tt.spec)
			if err == nil {
				t.Fatalf("validateRepoSpec(%q) = nil, want an error", tt.spec)
			}
			if strings.TrimSpace(err.Error()) == "" {
				t.Fatalf("validateRepoSpec(%q) returned an empty error message", tt.spec)
			}
		})
	}
}

func TestValidateRepoSpecErrorHints(t *testing.T) {
	t.Parallel()

	tests := []struct {
		spec     string
		contains string
	}{
		{"", "owner/repo"},
		{"noslash", "slash"},
		{"a/b/c", "slash"},
		{"/b", "owner"},
		{"a/", "empty"},
		{"a b/c", "space"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.spec, func(t *testing.T) {
			t.Parallel()
			err := validateRepoSpec(tt.spec)
			if err == nil {
				t.Fatalf("validateRepoSpec(%q) = nil, want an error", tt.spec)
			}
			if !strings.Contains(strings.ToLower(err.Error()), tt.contains) {
				t.Fatalf("validateRepoSpec(%q) = %q, want it to mention %q", tt.spec, err, tt.contains)
			}
		})
	}
}

func TestValidateCVEIDValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want string
	}{
		{"CVE-2024-1234", "CVE-2024-1234"},
		{"cve-2024-1234567", "CVE-2024-1234567"},
		{"Cve-1999-0001", "CVE-1999-0001"},
		{"  CVE-2024-1234  ", "CVE-2024-1234"},
		{"", ""},
		{"   ", ""},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			got, err := validateCVEID(tt.in)
			if err != nil {
				t.Fatalf("validateCVEID(%q) = %v, want nil", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("validateCVEID(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestValidateCVEIDInvalid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
	}{
		{"two digit year", "CVE-24-1"},
		{"ghsa", "GHSA-xxxx"},
		{"only three digits", "CVE-2024-123"},
		{"no separator", "CVE20241234"},
		{"missing id part", "CVE-2024-"},
		{"words", "not-a-cve"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := validateCVEID(tt.in)
			if err == nil {
				t.Fatalf("validateCVEID(%q) = %q, nil; want an error", tt.in, got)
			}
		})
	}
}

func TestValidateSummary(t *testing.T) {
	t.Parallel()

	if err := validateSummary("Heap overflow in the parser"); err != nil {
		t.Fatalf("valid summary rejected: %v", err)
	}
	if err := validateSummary("   "); err == nil {
		t.Fatal("blank summary accepted, want an error")
	}
	if err := validateSummary("line one\nline two"); err == nil {
		t.Fatal("multi-line summary accepted, want an error")
	}
	if err := validateSummary(strings.Repeat("a", summaryMaxLen)); err != nil {
		t.Fatalf("summary of exactly %d chars rejected: %v", summaryMaxLen, err)
	}
	if err := validateSummary(strings.Repeat("a", summaryMaxLen+1)); err == nil {
		t.Fatalf("summary of %d chars accepted, want an error", summaryMaxLen+1)
	}
}

func TestValidateToken(t *testing.T) {
	t.Parallel()

	valid := "ghp_" + strings.Repeat("a", 36)
	if err := validateToken(valid); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}

	invalid := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"blank", "   "},
		{"too short", "short"},
		{"contains space", "ghp_aaaaaaaaaaaaaaaa aaaa"},
		{"contains newline", "ghp_" + strings.Repeat("a", 20) + "\n"},
		{"surrounding space", " " + valid + " "},
	}
	for _, tt := range invalid {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := validateToken(tt.token); err == nil {
				t.Fatalf("validateToken(%q) = nil, want an error", tt.token)
			}
		})
	}
}

func TestValidateOptionalAlias(t *testing.T) {
	t.Parallel()

	valid := []string{"", "   ", "work", "my-org_1.2", strings.Repeat("a", 32)}
	for _, alias := range valid {
		if err := validateOptionalAlias(alias); err != nil {
			t.Fatalf("validateOptionalAlias(%q) = %v, want nil", alias, err)
		}
	}

	invalid := []string{"-work", ".work", "has space", "has/slash", strings.Repeat("a", 33)}
	for _, alias := range invalid {
		if err := validateOptionalAlias(alias); err == nil {
			t.Fatalf("validateOptionalAlias(%q) = nil, want an error", alias)
		}
	}
}

func TestMapFormErr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		err     error
		want    error
		wantNil bool
		aborted bool
	}{
		{name: "nil", err: nil, wantNil: true},
		{name: "user aborted", err: huh.ErrUserAborted, want: ErrAborted},
		{name: "wrapped user aborted", err: errors.Join(errors.New("ctx"), huh.ErrUserAborted), want: ErrAborted},
		{name: "io eof", err: io.EOF, want: ErrAborted},
		{name: "wrapped io eof", err: errors.Join(errors.New("read"), io.EOF), want: ErrAborted},
		{name: "boom", err: errors.New("boom"), aborted: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := mapFormErr(tt.err)
			if tt.wantNil {
				if got != nil {
					t.Fatalf("mapFormErr(nil) = %v, want nil", got)
				}
				return
			}
			if tt.want != nil {
				if !errors.Is(got, tt.want) {
					t.Fatalf("mapFormErr(%v) = %v, want %v", tt.err, got, tt.want)
				}
				return
			}
			if tt.aborted {
				if !errors.Is(got, ErrAborted) {
					t.Fatalf("mapFormErr(%v) = %v, want ErrAborted", tt.err, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("mapFormErr(%v) = nil, want a wrapped error", tt.err)
			}
			if errors.Is(got, ErrAborted) {
				t.Fatalf("mapFormErr(%v) = %v, want a non-abort error", tt.err, got)
			}
			if !errors.Is(got, tt.err) {
				t.Fatalf("mapFormErr(%v) = %v, want it to wrap the original", tt.err, got)
			}
		})
	}
}

func TestMapFormErrBoomMessage(t *testing.T) {
	t.Parallel()

	err := mapFormErr(errors.New("boom"))
	if err == nil {
		t.Fatal("mapFormErr(\"boom\") = nil, want an error")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Fatalf("mapFormErr(\"boom\") = %q, want it to mention the cause", err)
	}
}

func TestActionString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		action Action
		want   string
	}{
		{ActionReport, "report"},
		{ActionAdvisory, "advisory"},
		{ActionProfiles, "profiles"},
		{ActionQuit, "quit"},
	}

	for _, tt := range tests {
		if got := tt.action.String(); got != tt.want {
			t.Fatalf("Action(%d).String() = %q, want %q", int(tt.action), got, tt.want)
		}
	}

	if got := Action(42).String(); got == "" {
		t.Fatal("unknown Action should still render something")
	}
}

func TestProfActionString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		action ProfAction
		want   string
	}{
		{ProfSwitch, "switch"},
		{ProfAdd, "add"},
		{ProfDelete, "delete"},
		{ProfBack, "back"},
	}

	for _, tt := range tests {
		if got := tt.action.String(); got != tt.want {
			t.Fatalf("ProfAction(%d).String() = %q, want %q", int(tt.action), got, tt.want)
		}
	}

	if got := ProfAction(42).String(); got == "" {
		t.Fatal("unknown ProfAction should still render something")
	}
}

func TestSourceString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		source Source
		want   string
	}{
		{SourceFile, "file"},
		{SourceEditor, "editor"},
		{SourceInline, "inline"},
	}

	for _, tt := range tests {
		if got := tt.source.String(); got != tt.want {
			t.Fatalf("Source(%d).String() = %q, want %q", int(tt.source), got, tt.want)
		}
	}

	if got := Source(42).String(); got == "" {
		t.Fatal("unknown Source should still render something")
	}
}

func TestActionConstantsAreStable(t *testing.T) {
	t.Parallel()

	// main.go switches on these values, and the zero value must be ActionReport
	// so an unset variable never means "quit".
	if ActionReport != 0 || ActionAdvisory != 1 || ActionBrowse != 2 ||
		ActionProfiles != 3 || ActionQuit != 4 {
		t.Fatalf("Action constants drifted: %d %d %d %d %d",
			ActionReport, ActionAdvisory, ActionBrowse, ActionProfiles, ActionQuit)
	}
	if ProfSwitch != 0 || ProfAdd != 1 || ProfDelete != 2 || ProfBack != 3 {
		t.Fatalf("ProfAction constants drifted: %d %d %d %d",
			ProfSwitch, ProfAdd, ProfDelete, ProfBack)
	}
	if SourceFile != 0 || SourceEditor != 1 || SourceInline != 2 {
		t.Fatalf("Source constants drifted: %d %d %d", SourceFile, SourceEditor, SourceInline)
	}
}

func TestRunProfilePickerEmptyAliases(t *testing.T) {
	t.Parallel()

	// Must fail fast: no TTY is available in tests, so this proves the guard
	// runs before any form is constructed.
	got, err := RunProfilePicker(nil, "")
	if err == nil {
		t.Fatal("RunProfilePicker(nil) = nil error, want \"no profiles available\"")
	}
	if !strings.Contains(err.Error(), "no profiles") {
		t.Fatalf("RunProfilePicker(nil) = %q, want it to mention no profiles", err)
	}
	if errors.Is(err, ErrAborted) {
		t.Fatal("an empty profile list is a real error, not an abort")
	}
	if got != "" {
		t.Fatalf("RunProfilePicker(nil) = %q, want an empty alias", got)
	}

	if _, err := RunProfilePicker([]string{}, "work"); err == nil {
		t.Fatal("RunProfilePicker(empty) = nil error, want \"no profiles available\"")
	}
}

func TestNewReportFormBuilds(t *testing.T) {
	t.Parallel()

	in := &ReportInput{}
	form := newReportForm(in)
	if form == nil {
		t.Fatal("newReportForm returned nil")
	}

	// The form must be usable without a TTY: fields bind to the input struct.
	if form.GetFocusedField() == nil {
		t.Fatal("newReportForm produced a form without a focused field")
	}

	in.Repo = "octocat/Hello-World"
	in.Summary = "Heap overflow"
	in.Description = "Details"
	in.CVEID = "cve-2024-1234"
	if _, err := validateCVEID(in.CVEID); err != nil {
		t.Fatalf("prepared CVE ID invalid: %v", err)
	}
	in.CVEID = normalisedCVE(in.CVEID)
	if in.CVEID != "CVE-2024-1234" {
		t.Fatalf("normalisedCVE = %q, want %q", in.CVEID, "CVE-2024-1234")
	}
	if got := validateRepoSpec(in.Repo); got != nil {
		t.Fatalf("prepared repo invalid: %v", got)
	}
}

func TestNewReportFormDefaults(t *testing.T) {
	t.Parallel()

	in := &ReportInput{Repo: "octocat/Hello-World"}
	form := newReportForm(in)
	if form == nil {
		t.Fatal("newReportForm returned nil")
	}

	// Severity defaults to Medium when unset.
	if in.Severity != api.SeverityMedium {
		t.Fatalf("default severity = %q, want %q", in.Severity, api.SeverityMedium)
	}
	if in.Repo != "octocat/Hello-World" {
		t.Fatalf("repo prefill lost: %q", in.Repo)
	}
}

func TestNewReportFormNilInput(t *testing.T) {
	t.Parallel()

	if form := newReportForm(nil); form == nil {
		t.Fatal("newReportForm(nil) returned nil")
	}
}

func TestNewReportFormKeepsExplicitSeverity(t *testing.T) {
	t.Parallel()

	in := &ReportInput{Severity: api.SeverityHigh}
	if form := newReportForm(in); form == nil {
		t.Fatal("newReportForm returned nil")
	}
	if in.Severity != api.SeverityHigh {
		t.Fatalf("severity overwritten: %q", in.Severity)
	}
}

func TestNewAdvisoryFormBuilds(t *testing.T) {
	t.Parallel()

	in := &AdvisorInput{}
	form := newAdvisoryForm(in)
	if form == nil {
		t.Fatal("newAdvisoryForm returned nil")
	}
	if form.GetFocusedField() == nil {
		t.Fatal("newAdvisoryForm produced a form without a focused field")
	}
	if in.Severity != api.SeverityMedium {
		t.Fatalf("default severity = %q, want %q", in.Severity, api.SeverityMedium)
	}

	in.Affected = "<= 1.2.3"
	normaliseAdvisory(in)
	if in.Affected != "<= 1.2.3" {
		t.Fatalf("affected normalised to %q", in.Affected)
	}
}

func TestNewAdvisoryFormNilInput(t *testing.T) {
	t.Parallel()

	if form := newAdvisoryForm(nil); form == nil {
		t.Fatal("newAdvisoryForm(nil) returned nil")
	}
}

func TestNewOnboardingAndTokenFormsBuild(t *testing.T) {
	t.Parallel()

	in := &ProfileInput{}
	if form := newOnboardingForm(in); form == nil {
		t.Fatal("newOnboardingForm returned nil")
	}
	if form := newOnboardingForm(nil); form == nil {
		t.Fatal("newOnboardingForm(nil) returned nil")
	}
	if form := newTokenPromptForm(in); form == nil {
		t.Fatal("newTokenPromptForm returned nil")
	}
	if form := newTokenPromptForm(nil); form == nil {
		t.Fatal("newTokenPromptForm(nil) returned nil")
	}
}

func TestFinishProfileInputTrim(t *testing.T) {
	t.Parallel()

	in := &ProfileInput{Token: "  ghp_abc  ", Alias: "  work  "}
	finishProfileInput(in)
	if in.Token != "ghp_abc" {
		t.Fatalf("token = %q, want it trimmed", in.Token)
	}
	if in.Alias != "work" {
		t.Fatalf("alias = %q, want it trimmed", in.Alias)
	}

	blank := &ProfileInput{Token: "ghp_abc", Alias: "   "}
	finishProfileInput(blank)
	if blank.Alias != "" {
		t.Fatalf("blank alias = %q, want empty (use the GitHub username)", blank.Alias)
	}
}

func TestMenuFormsBuild(t *testing.T) {
	t.Parallel()

	action := ActionQuit
	if form := newMainMenuForm(&action, "work", "octocat"); form == nil {
		t.Fatal("newMainMenuForm returned nil")
	}
	if action != ActionReport {
		t.Fatalf("main menu default = %v, want the first option (ActionReport)", action)
	}
	if form := newMainMenuForm(nil, "", ""); form == nil {
		t.Fatal("newMainMenuForm(nil) returned nil")
	}

	profAction := ProfBack
	if form := newProfileMenuForm(&profAction, []string{"work", "home"}, "work"); form == nil {
		t.Fatal("newProfileMenuForm returned nil")
	}
	if profAction != ProfSwitch {
		t.Fatalf("profile menu default = %v, want ProfSwitch", profAction)
	}
	if form := newProfileMenuForm(nil, nil, ""); form == nil {
		t.Fatal("newProfileMenuForm(nil) returned nil")
	}

	source := SourceInline
	if form := newDescriptionSourceForm(&source); form == nil {
		t.Fatal("newDescriptionSourceForm returned nil")
	}
	if source != SourceFile {
		t.Fatalf("description source default = %v, want SourceFile", source)
	}
	if form := newDescriptionSourceForm(nil); form == nil {
		t.Fatal("newDescriptionSourceForm(nil) returned nil")
	}

	var confirmed bool
	if form := newConfirmForm("Proceed?", &confirmed); form == nil {
		t.Fatal("newConfirmForm returned nil")
	}
	if form := newNoteForm("Title", "Body"); form == nil {
		t.Fatal("newNoteForm returned nil")
	}

	var text string
	if form := newTextInputForm("Title", "Desc", "hint", nil, &text); form == nil {
		t.Fatal("newTextInputForm returned nil")
	}
	if form := newTextInputForm("Title", "", "", validateRepoSpec, &text); form == nil {
		t.Fatal("newTextInputForm without description/placeholder returned nil")
	}

	var desc string
	if form := newInlineDescriptionForm(&desc); form == nil {
		t.Fatal("newInlineDescriptionForm returned nil")
	}

	var repo string
	if form := newRepoInputForm(&repo); form == nil {
		t.Fatal("newRepoInputForm returned nil")
	}
}

func TestMainMenuDescriptionMentionsIdentity(t *testing.T) {
	t.Parallel()

	got := mainMenuDescription("work", "octocat")
	if !strings.Contains(got, "octocat") {
		t.Fatalf("main menu description missing username: %q", got)
	}
	if !strings.Contains(got, "work") {
		t.Fatalf("main menu description missing alias: %q", got)
	}

	// Empty strings must not produce dangling separators or panic.
	for _, desc := range []string{
		mainMenuDescription("", ""),
		mainMenuDescription("work", ""),
		mainMenuDescription("", "octocat"),
	} {
		if strings.TrimSpace(desc) == "" {
			t.Fatal("main menu description is empty")
		}
		if strings.Contains(desc, "()") || strings.Contains(desc, "profile: )") {
			t.Fatalf("main menu description has dangling punctuation: %q", desc)
		}
	}
}

func TestIdentityLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		alias, username string
		contains        []string
	}{
		{"work", "octocat", []string{"octocat", "work"}},
		{"", "octocat", []string{"octocat"}},
		{"work", "", []string{"work"}},
		{"", "", []string{"Not signed in"}},
	}

	for _, tt := range tests {
		got := identityLine(tt.alias, tt.username)
		for _, want := range tt.contains {
			if !strings.Contains(got, want) {
				t.Fatalf("identityLine(%q, %q) = %q, want it to mention %q",
					tt.alias, tt.username, got, want)
			}
		}
	}
}

func TestProfileMenuDescription(t *testing.T) {
	t.Parallel()

	if got := profileMenuDescription(nil, ""); !strings.Contains(got, "No profiles") {
		t.Fatalf("empty profile description = %q, want a \"No profiles\" hint", got)
	}
	if got := profileMenuDescription([]string{"work"}, "work"); !strings.Contains(got, "1 profile") {
		t.Fatalf("single profile description = %q", got)
	}
	if got := profileMenuDescription([]string{"work", "home"}, "home"); !strings.Contains(got, "2 profiles") {
		t.Fatalf("two profile description = %q", got)
	}
	if got := profileMenuDescription([]string{"work", "home"}, "home"); !strings.Contains(got, "home") {
		t.Fatalf("two profile description missing active alias: %q", got)
	}
}

func TestProfilePickerOptions(t *testing.T) {
	t.Parallel()

	opts := profilePickerOptions([]string{"work", "home"}, "work")
	if len(opts) != 2 {
		t.Fatalf("got %d options, want 2", len(opts))
	}
	if opts[0].Value != "work" || opts[1].Value != "home" {
		t.Fatalf("option values = %q, %q", opts[0].Value, opts[1].Value)
	}
	if !strings.Contains(opts[0].Key, "active") {
		t.Fatalf("active profile label = %q, want an active marker", opts[0].Key)
	}
	if strings.Contains(opts[1].Key, "active") {
		t.Fatalf("inactive profile label = %q, want no active marker", opts[1].Key)
	}

	// No active profile: no markers anywhere.
	for _, opt := range profilePickerOptions([]string{"work", "home"}, "") {
		if strings.Contains(opt.Key, "active") {
			t.Fatalf("option %q marked active with an empty active alias", opt.Key)
		}
	}
}

func TestProfilePickerOptionsEmpty(t *testing.T) {
	t.Parallel()

	if opts := profilePickerOptions(nil, "work"); len(opts) != 0 {
		t.Fatalf("got %d options, want 0", len(opts))
	}
}

func TestNoteSafeEscapesMarkdown(t *testing.T) {
	t.Parallel()

	got := noteSafe("use `public_repo` and *stars*")
	for _, want := range []string{"\\`", "\\_", "\\*"} {
		if !strings.Contains(got, want) {
			t.Fatalf("noteSafe(%q) = %q, want it to contain %q", "use `public_repo` and *stars*", got, want)
		}
	}
	if got := noteSafe("plain text"); got != "plain text" {
		t.Fatalf("noteSafe(\"plain text\") = %q, want it unchanged", got)
	}
}

func TestSeverityOptions(t *testing.T) {
	t.Parallel()

	opts := severityOptions()
	if len(opts) != len(api.SeverityLevels) {
		t.Fatalf("got %d severity options, want %d", len(opts), len(api.SeverityLevels))
	}
	if opts[0].Value != api.SeverityCritical {
		t.Fatalf("first severity = %q, want critical", opts[0].Value)
	}
	if opts[len(opts)-1].Value != api.SeverityLow {
		t.Fatalf("last severity = %q, want low", opts[len(opts)-1].Value)
	}
	for _, opt := range opts {
		if !opt.Value.Valid() {
			t.Fatalf("option %q has an invalid severity", opt.Key)
		}
		if strings.TrimSpace(opt.Key) == "" {
			t.Fatalf("severity %q has an empty label", opt.Value)
		}
	}
	if !strings.Contains(severityOptionLabel(api.SeverityCritical), "remote code execution") {
		t.Fatalf("critical label = %q, want the long description", severityOptionLabel(api.SeverityCritical))
	}
	if severityOptionLabel(api.SeverityHigh) != "High" {
		t.Fatalf("high label = %q, want %q", severityOptionLabel(api.SeverityHigh), "High")
	}
}

func TestValidateDescription(t *testing.T) {
	t.Parallel()

	if err := validateDescription("Some details"); err != nil {
		t.Fatalf("valid description rejected: %v", err)
	}
	for _, blank := range []string{"", "   ", "\n", "\t\n "} {
		if err := validateDescription(blank); err == nil {
			t.Fatalf("validateDescription(%q) = nil, want an error", blank)
		}
	}
}

func TestNormalisedCVE(t *testing.T) {
	t.Parallel()

	if got := normalisedCVE(" cve-2024-1234 "); got != "CVE-2024-1234" {
		t.Fatalf("normalisedCVE = %q, want %q", got, "CVE-2024-1234")
	}
	if got := normalisedCVE(""); got != "" {
		t.Fatalf("normalisedCVE(\"\") = %q, want empty", got)
	}
}

func TestNormaliseReport(t *testing.T) {
	t.Parallel()

	in := &ReportInput{
		Repo:        "  octocat/Hello-World  ",
		Summary:     "  Heap overflow  ",
		Description: "  Details  ",
		CVEID:       "cve-2024-1234",
	}
	normaliseReport(in)

	if in.Repo != "octocat/Hello-World" {
		t.Fatalf("repo = %q, want it trimmed", in.Repo)
	}
	if in.Summary != "Heap overflow" {
		t.Fatalf("summary = %q, want it trimmed", in.Summary)
	}
	if in.Description != "Details" {
		t.Fatalf("description = %q, want it trimmed", in.Description)
	}
	if in.CVEID != "CVE-2024-1234" {
		t.Fatalf("cve = %q, want it upper-cased", in.CVEID)
	}
}

func TestErrAbortedIsSentinel(t *testing.T) {
	t.Parallel()

	if ErrAborted == nil {
		t.Fatal("ErrAborted is nil")
	}
	if !errors.Is(ErrAborted, ErrAborted) {
		t.Fatal("ErrAborted does not satisfy errors.Is against itself")
	}
	if errors.Is(ErrAborted, huh.ErrUserAborted) {
		t.Fatal("ErrAborted must be its own sentinel, not huh.ErrUserAborted")
	}
	if got := ErrAborted.Error(); got != "aborted" {
		t.Fatalf("ErrAborted.Error() = %q, want %q", got, "aborted")
	}
}
