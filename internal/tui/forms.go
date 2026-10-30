package tui

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/charmbracelet/huh"

	"github.com/yuuuuukiu/ghsec/internal/api"
)

// ReportInput is the data gathered by RunPrivateReportForm.
type ReportInput struct {
	Repo        string
	Summary     string
	Severity    api.Severity
	CVEID       string
	Description string
}

// AdvisorInput is the data gathered by RunAdvisoryForm.
type AdvisorInput struct {
	Repo        string
	Summary     string
	Severity    api.Severity
	CVEID       string
	Description string
	Affected    string
}

// ProfileInput is the data gathered by RunOnboarding and RunTokenPrompt.
type ProfileInput struct {
	Token string
	Alias string
}

// Limits mirrored by the validators below. They match what GitHub accepts so
// the server does not have to be the first line of defence.
const (
	summaryMaxLen = 256
	tokenMinLen   = 20
)

var (
	// repoSpecPattern matches "owner/repo" with GitHub's character set and
	// length limits (owner <= 39 bytes, repo <= 100 bytes).
	repoSpecPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,38}/[A-Za-z0-9._-]{1,100}$`)

	// cveIDPattern matches a CVE identifier, case-insensitively.
	cveIDPattern = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,}$`)

	// aliasPattern mirrors config.ValidateAlias without importing the config
	// package, which is owned by another layer.
	aliasPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)
)

// validateRepoSpec checks a "owner/repo" spec and returns a friendly error.
// It is deliberately kept local to the TUI so that the api package's own
// parser can evolve independently.
func validateRepoSpec(spec string) error {
	if strings.TrimSpace(spec) == "" {
		return fmt.Errorf("enter a repository as owner/repo")
	}
	if strings.TrimSpace(spec) != spec {
		return fmt.Errorf("remove the leading or trailing whitespace")
	}
	for _, r := range spec {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return fmt.Errorf("no spaces allowed - use owner/repo, e.g. octocat/Hello-World")
		}
	}
	if n := strings.Count(spec, "/"); n != 1 {
		if n == 0 {
			return fmt.Errorf("no slash found - use owner/repo, e.g. octocat/Hello-World")
		}
		return fmt.Errorf("exactly one slash expected - found %d in %q", n, spec)
	}

	owner, repo, _ := strings.Cut(spec, "/")
	if owner == "" {
		return fmt.Errorf("owner is empty - use owner/repo, e.g. octocat/Hello-World")
	}
	if repo == "" {
		return fmt.Errorf("repository name is empty - use owner/repo, e.g. octocat/Hello-World")
	}
	if !repoSpecPattern.MatchString(spec) {
		return fmt.Errorf("invalid repository %q: use owner/repo, 39 chars max for the owner and 100 for the repo, letters, digits, '.', '_' and '-' only", spec)
	}
	return nil
}

// repoValidator adapts validateRepoSpec to huh's validator signature.
func repoValidator(spec string) error { return validateRepoSpec(spec) }

// validateCVEID validates an optional CVE identifier and returns it upper-cased
// so the stored value matches GitHub's convention. An empty value is valid and
// yields an empty string.
func validateCVEID(id string) (string, error) {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" {
		return "", nil
	}
	if !cveIDPattern.MatchString(trimmed) {
		return "", fmt.Errorf("invalid CVE ID %q: expected CVE-YYYY-NNNN, e.g. CVE-2024-1234", id)
	}
	return strings.ToUpper(trimmed), nil
}

// cveValidator adapts validateCVEID to huh's validator signature.
func cveValidator(id string) error {
	_, err := validateCVEID(id)
	return err
}

// validateSummary enforces GitHub's 1..256 single-line summary rule.
func validateSummary(summary string) error {
	trimmed := strings.TrimSpace(summary)
	if trimmed == "" {
		return fmt.Errorf("summary must not be empty")
	}
	if strings.ContainsAny(trimmed, "\r\n") {
		return fmt.Errorf("summary must be a single line")
	}
	if utf8.RuneCountInString(trimmed) > summaryMaxLen {
		return fmt.Errorf("summary must be at most %d characters (currently %d)",
			summaryMaxLen, utf8.RuneCountInString(trimmed))
	}
	return nil
}

// validateDescription requires a non-empty description once trimmed.
func validateDescription(desc string) error {
	if strings.TrimSpace(desc) == "" {
		return fmt.Errorf("description must not be empty - Markdown is supported")
	}
	return nil
}

// validateToken checks a GitHub personal access token without any network I/O.
func validateToken(token string) error {
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("token must not be empty")
	}
	if strings.TrimSpace(token) != token {
		return fmt.Errorf("token must not start or end with whitespace")
	}
	if strings.ContainsAny(token, " \t\r\n") {
		return fmt.Errorf("token must not contain spaces or newlines")
	}
	if utf8.RuneCountInString(token) < tokenMinLen {
		return fmt.Errorf("token looks too short (minimum %d characters)", tokenMinLen)
	}
	return nil
}

// validateOptionalAlias allows a blank alias ("use the GitHub username") and
// otherwise applies the profile alias rules.
func validateOptionalAlias(alias string) error {
	if strings.TrimSpace(alias) == "" {
		return nil
	}
	if !aliasPattern.MatchString(alias) {
		return fmt.Errorf("alias must start with a letter or digit and contain only letters, digits, '.', '_' or '-' (32 chars max)")
	}
	return nil
}

// severityHints holds the extra explanation shown for a severity. Only the
// strongest level gets a long label; the others stay terse so the picker fits
// on one screen.
var severityHints = map[api.Severity]string{
	api.SeverityCritical: "actively exploitable, remote code execution",
}

// severityOptionLabel renders a select label for a severity.
func severityOptionLabel(sev api.Severity) string {
	label := api.SeverityLabel(sev)
	if hint, ok := severityHints[sev]; ok && hint != "" {
		return label + " \u2014 " + hint
	}
	return label
}

// severityOptions lists every severity offered in the forms, in GitHub's
// descending order of impact.
func severityOptions() []huh.Option[api.Severity] {
	levels := api.SeverityLevels
	if len(levels) == 0 {
		levels = []api.Severity{
			api.SeverityCritical, api.SeverityHigh, api.SeverityMedium, api.SeverityLow,
		}
	}
	opts := make([]huh.Option[api.Severity], 0, len(levels))
	for _, sev := range levels {
		opts = append(opts, huh.NewOption(severityOptionLabel(sev), sev))
	}
	return opts
}

// newRepoInput builds a validated repository field.
func newRepoInput(defaultRepo string, value *string) *huh.Input {
	if defaultRepo != "" {
		*value = strings.TrimSpace(defaultRepo)
	}
	return huh.NewInput().
		Title("Repository").
		Description("owner/repo, e.g. octocat/Hello-World").
		Placeholder("octocat/Hello-World").
		Value(value).
		Validate(repoValidator)
}

// newSeveritySelect builds the shared severity picker, defaulting to Medium.
func newSeveritySelect(value *api.Severity) *huh.Select[api.Severity] {
	if !value.Valid() {
		*value = api.SeverityMedium
	}
	return huh.NewSelect[api.Severity]().
		Title("Severity").
		Description("How severe is the issue? You can change this later.").
		Options(severityOptions()...).
		Value(value)
}

// newCVEInput builds the optional CVE ID field.
func newCVEInput(value *string) *huh.Input {
	return huh.NewInput().
		Title("CVE ID (optional)").
		Description("Leave blank if there is no CVE yet. Example: CVE-2024-1234").
		Placeholder("CVE-2024-1234").
		Value(value).
		Validate(cveValidator)
}

// newSummaryInput builds the shared summary field.
func newSummaryInput(value *string) *huh.Input {
	return huh.NewInput().
		Title("Summary").
		Description("One line that describes the vulnerability (maximum 256 characters).").
		Placeholder("Path traversal in the archive extractor").
		CharLimit(summaryMaxLen).
		Value(value).
		Validate(validateSummary)
}

// newDescriptionField builds the multi-line description entry used inline.
func newDescriptionField(value *string, lines int) *huh.Text {
	return huh.NewText().
		Title("Description").
		Description("Markdown is supported. Enter submits, alt+enter (or ctrl+j) starts a new line.").
		Lines(lines).
		Value(value).
		Validate(validateDescription)
}

// newReportForm builds the private vulnerability report form without running it.
func newReportForm(in *ReportInput) *huh.Form {
	if in == nil {
		in = &ReportInput{}
	}

	return huh.NewForm(
		huh.NewGroup(newRepoInput(in.Repo, &in.Repo)).
			Title("Private vulnerability report").
			Description("Step 1 of 5 - which repository is affected?"),
		huh.NewGroup(newSummaryInput(&in.Summary)).
			Title("Step 2 of 5 - summary").
			Description("A short, specific title helps maintainers triage quickly."),
		huh.NewGroup(newSeveritySelect(&in.Severity)).
			Title("Step 3 of 5 - severity").
			Description("Pick the level that best matches the impact."),
		huh.NewGroup(newCVEInput(&in.CVEID)).
			Title("Step 4 of 5 - CVE").
			Description("Optional, but useful if a CVE has already been assigned."),
		huh.NewGroup(newDescriptionField(&in.Description, 8)).
			Title("Step 5 of 5 - description").
			Description("Explain the vulnerability, its impact and how to reproduce it."),
	).WithTheme(Theme()).WithShowHelp(true)
}

// newAdvisoryForm builds the maintainer advisory draft form without running it.
func newAdvisoryForm(in *AdvisorInput) *huh.Form {
	if in == nil {
		in = &AdvisorInput{}
	}

	return huh.NewForm(
		huh.NewGroup(newRepoInput(in.Repo, &in.Repo)).
			Title("Security advisory draft").
			Description("Step 1 of 6 - which repository is affected?"),
		huh.NewGroup(newSummaryInput(&in.Summary)).
			Title("Step 2 of 6 - summary").
			Description("A short, specific title helps users understand the risk."),
		huh.NewGroup(newSeveritySelect(&in.Severity)).
			Title("Step 3 of 6 - severity").
			Description("Pick the level that best matches the impact."),
		huh.NewGroup(newCVEInput(&in.CVEID)).
			Title("Step 4 of 6 - CVE").
			Description("Optional, but useful if a CVE has already been assigned."),
		huh.NewGroup(newDescriptionField(&in.Description, 8)).
			Title("Step 5 of 6 - description").
			Description("Explain the vulnerability, its impact and how to reproduce it."),
		huh.NewGroup(
			huh.NewText().
				Title("Affected versions").
				Description("Affected version ranges (one per line), e.g. \">= 1.0.0, < 1.2.3\"").
				Placeholder("<= 1.2.3\n>= 2.0.0, < 2.1.4").
				Lines(3).
				Value(&in.Affected),
		).Title("Step 6 of 6 - affected versions").
			Description("Let users check whether their version is vulnerable."),
	).WithTheme(Theme()).WithShowHelp(true)
}

// normaliseReport trims the collected values and normalises the CVE ID.
func normaliseReport(in *ReportInput) {
	in.Repo = strings.TrimSpace(in.Repo)
	in.Summary = strings.TrimSpace(in.Summary)
	in.Description = strings.TrimSpace(in.Description)
	in.CVEID = normalisedCVE(in.CVEID)
}

// normaliseAdvisory trims the collected values of an advisory draft.
func normaliseAdvisory(in *AdvisorInput) {
	in.Repo = strings.TrimSpace(in.Repo)
	in.Summary = strings.TrimSpace(in.Summary)
	in.Description = strings.TrimSpace(in.Description)
	in.Affected = strings.TrimSpace(in.Affected)
	in.CVEID = normalisedCVE(in.CVEID)
}

// normalisedCVE upper-cases a CVE ID, ignoring invalid leftovers.
func normalisedCVE(id string) string {
	if normalised, err := validateCVEID(id); err == nil {
		return normalised
	}
	return strings.ToUpper(strings.TrimSpace(id))
}

// RunPrivateReportForm collects the data for a private vulnerability report.
func RunPrivateReportForm(defaultRepo string) (*ReportInput, error) {
	in := &ReportInput{Repo: defaultRepo}
	if err := runForm(newReportForm(in)); err != nil {
		return nil, err
	}
	normaliseReport(in)
	return in, nil
}

// RunAdvisoryForm collects the data for a maintainer security advisory draft.
func RunAdvisoryForm(defaultRepo string) (*AdvisorInput, error) {
	in := &AdvisorInput{Repo: defaultRepo}
	if err := runForm(newAdvisoryForm(in)); err != nil {
		return nil, err
	}
	normaliseAdvisory(in)
	return in, nil
}

// onboardingNote is the introductory copy shown before the token prompt.
func onboardingNote() string {
	return strings.Join([]string{
		"ghsec needs a GitHub personal access token (PAT) to talk to GitHub for you.",
		"",
		"1. Open https://github.com/settings/tokens",
		"2. Generate a classic token with the `repo` scope",
		"   (or `public_repo` if you only report on public repositories).",
		"   Fine-grained tokens need 'Security events' read and write access.",
		"3. Paste it on the next screen.",
		"",
		"The token is stored locally with owner-only (0600) permissions and is",
		"only ever sent to api.github.com.",
	}, "\n")
}

// newTokenInput builds the masked token entry field.
func newTokenInput(token *string) *huh.Input {
	return huh.NewInput().
		Title("GitHub token").
		Description("Input is hidden. The token never leaves your machine except to call GitHub.").
		Placeholder("ghp_...").
		EchoMode(huh.EchoModePassword).
		Value(token).
		Validate(validateToken)
}

// newAliasInput builds the optional profile alias field.
func newAliasInput(alias *string) *huh.Input {
	return huh.NewInput().
		Title("Profile name (optional)").
		Description("Useful when you keep several tokens around.").
		Placeholder("leave blank to use your GitHub username").
		Value(alias).
		Validate(validateOptionalAlias)
}

// newOnboardingForm builds the first-run wizard without running it.
func newOnboardingForm(in *ProfileInput) *huh.Form {
	if in == nil {
		in = &ProfileInput{}
	}

	return huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title("Welcome to ghsec").
				Description(noteSafe(onboardingNote())).
				Next(true).
				NextLabel("Got it"),
		),
		huh.NewGroup(newTokenInput(&in.Token)).
			Title("Authentication"),
		huh.NewGroup(newAliasInput(&in.Alias)).
			Title("Profile"),
	).WithTheme(Theme()).WithShowHelp(true)
}

// newTokenPromptForm builds the add-profile form without running it.
func newTokenPromptForm(in *ProfileInput) *huh.Form {
	if in == nil {
		in = &ProfileInput{}
	}

	return huh.NewForm(
		huh.NewGroup(newTokenInput(&in.Token), newAliasInput(&in.Alias)).
			Title("Add a new API key").
			Description("Stored locally with owner-only permissions. No network calls are made here."),
	).WithTheme(Theme()).WithShowHelp(true)
}

// finishProfileInput trims the collected credentials.
func finishProfileInput(in *ProfileInput) {
	in.Token = strings.TrimSpace(in.Token)
	in.Alias = strings.TrimSpace(in.Alias)
}

// RunOnboarding walks a first-time user through creating a token and stores it
// in the returned ProfileInput. It never performs network I/O.
func RunOnboarding() (*ProfileInput, error) {
	in := &ProfileInput{}
	if err := runForm(newOnboardingForm(in)); err != nil {
		return nil, err
	}
	finishProfileInput(in)
	return in, nil
}

// RunTokenPrompt asks for a token and an optional alias, without verifying the
// token against GitHub.
func RunTokenPrompt() (*ProfileInput, error) {
	in := &ProfileInput{}
	if err := runForm(newTokenPromptForm(in)); err != nil {
		return nil, err
	}
	finishProfileInput(in)
	return in, nil
}

// newTextInputForm builds a single validated input.
func newTextInputForm(title, desc, placeholder string, validate func(string) error, value *string) *huh.Form {
	input := huh.NewInput().
		Title(title).
		Placeholder(placeholder).
		Value(value)
	if desc != "" {
		input = input.Description(desc)
	}
	if validate != nil {
		input = input.Validate(validate)
	}

	return huh.NewForm(
		huh.NewGroup(input),
	).WithTheme(Theme()).WithShowHelp(true)
}

// RunTextInput asks for a single line of text, optionally validated.
func RunTextInput(title, desc, placeholder string, validate func(string) error) (string, error) {
	var value string
	if err := runForm(newTextInputForm(title, desc, placeholder, validate, &value)); err != nil {
		return "", err
	}
	return strings.TrimSpace(value), nil
}

// newInlineDescriptionForm builds the multi-line description entry form.
func newInlineDescriptionForm(value *string) *huh.Form {
	return huh.NewForm(
		huh.NewGroup(newDescriptionField(value, 10)).
			Title("Describe the vulnerability"),
	).WithTheme(Theme()).WithShowHelp(true)
}

// RunInlineDescription collects a free-form, multi-line description inside a
// huh form. Enter submits; alt+enter or ctrl+j inserts a newline.
func RunInlineDescription() (string, error) {
	var value string
	if err := runForm(newInlineDescriptionForm(&value)); err != nil {
		return "", err
	}
	return strings.TrimSpace(value), nil
}

// newRepoInputForm builds the standalone repository prompt.
func newRepoInputForm(value *string) *huh.Form {
	return huh.NewForm(
		huh.NewGroup(newRepoInput(*value, value)).
			Title("Repository"),
	).WithTheme(Theme()).WithShowHelp(true)
}

// RunRepoInput asks for a validated owner/repo spec, pre-filled with
// defaultRepo when it is not empty.
func RunRepoInput(defaultRepo string) (string, error) {
	value := defaultRepo
	if err := runForm(newRepoInputForm(&value)); err != nil {
		return "", err
	}
	return strings.TrimSpace(value), nil
}
