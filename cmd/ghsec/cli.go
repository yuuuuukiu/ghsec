package main

// This file implements the non-interactive command surface: subcommands and
// flags that let ghsec run in scripts, CI pipelines and cron jobs without ever
// starting the TUI. The TUI remains the default when no arguments are given.
//
// Design rules for the CLI:
//   - stdout carries machine-readable data, stderr carries diagnostics.
//   - Nothing prompts unless stdin AND stdout are a TTY; otherwise --yes is
//     required, so a forgotten pipe can never submit a report silently.
//   - Credentials resolve from --token, then GITHUB_TOKEN / GH_TOKEN, then the
//     active stored profile, so CI needs no config file at all.
//   - Usage mistakes exit 2, runtime failures exit 1, success exits 0.

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/mattn/go-isatty"

	"github.com/yuuuuukiu/ghsec/internal/api"
	"github.com/yuuuuukiu/ghsec/internal/config"
	"github.com/yuuuuukiu/ghsec/internal/editor"
	"github.com/yuuuuukiu/ghsec/internal/tui"
)

// Exit codes used by the CLI surface.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

// defaultRequestTimeout bounds a single submission made from the CLI.
const defaultRequestTimeout = 60 * time.Second

// usageError marks a problem with how the command was invoked, so main can
// distinguish "you typed it wrong" (exit 2) from "it failed" (exit 1).
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

// usagef builds a usage error.
func usagef(format string, args ...any) error {
	return &usageError{msg: fmt.Sprintf(format, args...)}
}

// isUsageError reports whether err was caused by invalid invocation.
func isUsageError(err error) bool {
	var target *usageError
	return errors.As(err, &target)
}

// stdoutIsTTY reports whether stdout is an interactive terminal.
func stdoutIsTTY() bool {
	return isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())
}

// stdinIsTTY reports whether stdin is an interactive terminal.
func stdinIsTTY() bool {
	return isatty.IsTerminal(os.Stdin.Fd()) || isatty.IsCygwinTerminal(os.Stdin.Fd())
}

// clientFlags select which credential and API endpoint a command uses.
type clientFlags struct {
	token   string
	profile string
	apiURL  string
}

// register adds the shared credential flags to a flag set.
func (c *clientFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&c.token, "token", "", "GitHub token (default: $GITHUB_TOKEN, $GH_TOKEN, then the active profile)")
	fs.StringVar(&c.profile, "profile", "", "stored profile alias to use (default: the active profile)")
	fs.StringVar(&c.apiURL, "api-url", "", "API root for GitHub Enterprise Server (default: $GITHUB_API_URL)")
}

// resolve returns a client and a short description of where the token came from.
func (c *clientFlags) resolve() (*api.Client, string, error) {
	token := strings.TrimSpace(c.token)
	source := "--token flag"

	if token == "" {
		if v := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); v != "" {
			token, source = v, "$GITHUB_TOKEN"
		} else if v := strings.TrimSpace(os.Getenv("GH_TOKEN")); v != "" {
			token, source = v, "$GH_TOKEN"
		}
	}

	if token == "" {
		cfg, err := config.Load()
		if err != nil && !errors.Is(err, config.ErrNoConfig) {
			return nil, "", fmt.Errorf("read configuration: %w", err)
		}
		if cfg == nil || cfg.IsEmpty() {
			return nil, "", usagef(
				"no GitHub token available: pass --token, set GITHUB_TOKEN, or run `ghsec` once to store a profile")
		}
		if c.profile != "" {
			p, ok := cfg.Profiles[c.profile]
			if !ok {
				return nil, "", usagef("profile %q does not exist (available: %s)",
					c.profile, strings.Join(cfg.Aliases(), ", "))
			}
			token, source = p.Token, "profile "+c.profile
		} else {
			alias, p, ok := cfg.Active()
			if !ok {
				return nil, "", usagef(
					"no GitHub token available: pass --token, set GITHUB_TOKEN, or run `ghsec` once to store a profile")
			}
			token, source = p.Token, "profile "+alias
		}
	} else if c.profile != "" {
		return nil, "", usagef("--token and --profile are mutually exclusive")
	}

	baseURL := strings.TrimSpace(c.apiURL)
	if baseURL == "" {
		baseURL = api.BaseURLFromEnv()
	}

	var client *api.Client
	if baseURL == api.DefaultBaseURL {
		client = api.NewClient(token)
	} else {
		client = api.NewClientWithOptions(token, api.WithBaseURL(baseURL))
	}
	return client, source, nil
}

// writeFlags are the shared inputs for the two write commands.
type writeFlags struct {
	clientFlags

	repo        string
	summary     string
	severity    string
	cve         string
	description string
	descFile    string
	affected    string
	yes         bool
	asJSON      bool
	dryRun      bool
	timeout     time.Duration
}

// register adds the shared write flags to a flag set.
func (w *writeFlags) register(fs *flag.FlagSet, wantAffected bool) {
	w.clientFlags.register(fs)
	fs.StringVar(&w.repo, "repo", "", "target repository as owner/repo (required)")
	fs.StringVar(&w.summary, "summary", "", "one-line summary (required)")
	fs.StringVar(&w.severity, "severity", string(api.SeverityMedium),
		"severity: critical, high, medium or low")
	fs.StringVar(&w.cve, "cve", "", "optional CVE identifier, for example CVE-2026-12345")
	fs.StringVar(&w.description, "description", "", "description body as inline text")
	fs.StringVar(&w.descFile, "description-file", "",
		"read the description from a file, or - for stdin")
	if wantAffected {
		fs.StringVar(&w.affected, "affected", "", "affected version ranges, one per line")
	}
	fs.BoolVar(&w.yes, "yes", false, "submit without prompting for confirmation")
	fs.BoolVar(&w.asJSON, "json", false, "print a machine-readable JSON result on stdout")
	fs.BoolVar(&w.dryRun, "dry-run", false, "validate and show what would be sent, without calling GitHub")
	fs.DurationVar(&w.timeout, "timeout", defaultRequestTimeout, "request timeout")
}

// validate checks the shared inputs and normalises them.
func (w *writeFlags) validate() (owner, repo string, sev api.Severity, description string, err error) {
	owner, repo, err = api.ValidateRepoSpec(w.repo)
	if err != nil {
		return "", "", "", "", usagef("%v", err)
	}

	if strings.TrimSpace(w.summary) == "" {
		return "", "", "", "", usagef("--summary must not be empty")
	}
	if len([]rune(w.summary)) > 256 {
		return "", "", "", "", usagef("--summary must be at most 256 characters (got %d)", len([]rune(w.summary)))
	}

	sev, err = api.ParseSeverity(w.severity)
	if err != nil {
		return "", "", "", "", usagef("%v", err)
	}

	if err := validateCVE(w.cve); err != nil {
		return "", "", "", "", err
	}

	description, err = w.readDescription()
	if err != nil {
		return "", "", "", "", err
	}
	return owner, repo, sev, description, nil
}

// readDescription resolves the description from --description, --description-file
// or stdin, rejecting ambiguous or empty combinations.
func (w *writeFlags) readDescription() (string, error) {
	inlineSet := strings.TrimSpace(w.description) != ""
	fileSet := strings.TrimSpace(w.descFile) != ""

	switch {
	case inlineSet && fileSet:
		return "", usagef("use either --description or --description-file, not both")
	case fileSet:
		if strings.TrimSpace(w.descFile) == "-" {
			raw, err := io.ReadAll(io.LimitReader(os.Stdin, 8<<20))
			if err != nil {
				return "", fmt.Errorf("read the description from stdin: %w", err)
			}
			if strings.TrimSpace(string(raw)) == "" {
				return "", usagef("stdin was empty: pipe the description in, or use --description")
			}
			return strings.TrimSpace(string(raw)), nil
		}
		content, err := editor.ReadFile(w.descFile)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(content), nil
	case inlineSet:
		return strings.TrimSpace(w.description), nil
	default:
		return "", usagef("a description is required: pass --description, --description-file PATH, or --description-file - for stdin")
	}
}

// confirmSubmit gates a write behind explicit consent.
//
// Non-interactive invocations must pass --yes: that makes an accidental pipe or
// a forgotten flag fail loudly instead of filing a vulnerability report.
func confirmSubmit(autoYes bool, prompt string) (bool, error) {
	if autoYes {
		return true, nil
	}
	if !stdinIsTTY() || !stdoutIsTTY() {
		return false, usagef("refusing to submit without confirmation: pass --yes for non-interactive use")
	}
	ok, err := tui.RunConfirm(prompt, false)
	if err != nil {
		if errors.Is(err, tui.ErrAborted) {
			return false, tui.ErrAborted
		}
		return false, err
	}
	return ok, nil
}

// result is the stable JSON shape printed by --json.
type result struct {
	OK         bool   `json:"ok"`
	DryRun     bool   `json:"dry_run,omitempty"`
	Repository string `json:"repository"`
	ID         string `json:"id,omitempty"`
	GHSAID     string `json:"ghsa_id,omitempty"`
	CVEID      string `json:"cve_id,omitempty"`
	Summary    string `json:"summary"`
	Severity   string `json:"severity"`
	State      string `json:"state,omitempty"`
	URL        string `json:"url,omitempty"`
}

// emit writes the outcome either as JSON (for scripts) or as readable text.
func emit(w io.Writer, r result, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}

	if r.DryRun {
		fmt.Fprintf(w, "dry run: nothing was sent\n")
		fmt.Fprintf(w, "  repository: %s\n", r.Repository)
		fmt.Fprintf(w, "  summary:    %s\n", r.Summary)
		fmt.Fprintf(w, "  severity:   %s\n", r.Severity)
		if r.CVEID != "" {
			fmt.Fprintf(w, "  cve:        %s\n", r.CVEID)
		}
		return nil
	}

	fmt.Fprintf(w, "created %s\n", r.ID)
	fmt.Fprintf(w, "  repository: %s\n", r.Repository)
	fmt.Fprintf(w, "  severity:   %s\n", r.Severity)
	if r.State != "" {
		fmt.Fprintf(w, "  state:      %s\n", r.State)
	}
	if r.CVEID != "" {
		fmt.Fprintf(w, "  cve:        %s\n", r.CVEID)
	}
	if r.URL != "" {
		fmt.Fprintf(w, "  url:        %s\n", r.URL)
	}
	return nil
}

// buildFlagSet creates a flag set that reports errors instead of exiting, and
// whose diagnostics are suppressed so the caller controls the message.
func buildFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// parseFlags parses args and converts flag errors into usage errors.
func parseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return errFlagHandled
		}
		return usagef("%s: %v", fs.Name(), err)
	}
	if fs.NArg() > 0 {
		return usagef("%s: unexpected argument %q", fs.Name(), fs.Arg(0))
	}
	return nil
}

// runReportCmd implements `ghsec report`.
func runReportCmd(ctx context.Context, args []string) error {
	var w writeFlags
	fs := buildFlagSet("report")
	w.register(fs, false)
	fs.Usage = func() { fmt.Fprint(os.Stderr, reportUsage) }
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	owner, repo, sev, description, err := w.validate()
	if err != nil {
		return err
	}

	req := api.PrivateReportRequest{
		Summary:     strings.TrimSpace(w.summary),
		Description: description,
		Severity:    sev,
		CVEID:       strings.ToUpper(strings.TrimSpace(w.cve)),
	}

	res := result{
		OK:         true,
		DryRun:     w.dryRun,
		Repository: owner + "/" + repo,
		Summary:    req.Summary,
		Severity:   string(sev),
		CVEID:      req.CVEID,
	}

	if w.dryRun {
		return emit(os.Stdout, res, w.asJSON)
	}

	client, source, err := w.clientFlags.resolve()
	if err != nil {
		return err
	}

	ok, err := confirmSubmit(w.yes, fmt.Sprintf("Submit a private vulnerability report to %s/%s?", owner, repo))
	if err != nil {
		return err
	}
	if !ok {
		fmt.Fprintln(os.Stderr, "cancelled: nothing was sent")
		return errCancelled
	}

	callCtx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()

	advisory, err := client.SubmitPrivateReport(callCtx, owner, repo, req)
	if err != nil {
		return fmt.Errorf("%s: %w", api.FriendlyMessage(err, "submit the private report"), err)
	}

	res.ID = advisory.Identifier()
	res.GHSAID = advisory.GHSAID
	res.CVEID = firstNonEmpty(advisory.CVEID, res.CVEID)
	res.State = advisory.State
	res.URL = advisory.HTMLURL

	recordCLIHistory(config.KindReport, owner, repo, req.Summary, string(sev), advisory)

	if !w.asJSON {
		fmt.Fprintf(os.Stderr, "authenticated with %s\n", source)
	}
	return emit(os.Stdout, res, w.asJSON)
}

// runAdvisoryCmd implements `ghsec advisory`.
func runAdvisoryCmd(ctx context.Context, args []string) error {
	var w writeFlags
	fs := buildFlagSet("advisory")
	w.register(fs, true)
	fs.Usage = func() { fmt.Fprint(os.Stderr, advisoryUsage) }
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	owner, repo, sev, description, err := w.validate()
	if err != nil {
		return err
	}

	req := api.AdvisoryDraftRequest{
		Summary:      strings.TrimSpace(w.summary),
		Description:  description,
		Severity:     sev,
		CVEID:        strings.ToUpper(strings.TrimSpace(w.cve)),
		AffectedText: strings.TrimSpace(w.affected),
	}

	res := result{
		OK:         true,
		DryRun:     w.dryRun,
		Repository: owner + "/" + repo,
		Summary:    req.Summary,
		Severity:   string(sev),
		CVEID:      req.CVEID,
	}
	if w.dryRun {
		return emit(os.Stdout, res, w.asJSON)
	}

	client, source, err := w.clientFlags.resolve()
	if err != nil {
		return err
	}

	ok, err := confirmSubmit(w.yes, fmt.Sprintf("Create a draft security advisory in %s/%s?", owner, repo))
	if err != nil {
		return err
	}
	if !ok {
		fmt.Fprintln(os.Stderr, "cancelled: nothing was sent")
		return errCancelled
	}

	callCtx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()

	advisory, err := client.CreateAdvisoryDraft(callCtx, owner, repo, req)
	if err != nil {
		return fmt.Errorf("%s: %w", api.FriendlyMessage(err, "create the advisory draft"), err)
	}

	res.ID = advisory.Identifier()
	res.GHSAID = advisory.GHSAID
	res.CVEID = firstNonEmpty(advisory.CVEID, res.CVEID)
	res.State = advisory.State
	res.URL = advisory.HTMLURL

	recordCLIHistory(config.KindAdvisory, owner, repo, req.Summary, string(sev), advisory)

	if !w.asJSON {
		fmt.Fprintf(os.Stderr, "authenticated with %s\n", source)
	}
	return emit(os.Stdout, res, w.asJSON)
}

// profileView is one row of `ghsec profile list`.
type profileView struct {
	Alias    string `json:"alias"`
	Username string `json:"username"`
	Token    string `json:"token"`
	Active   bool   `json:"active"`
}

// runProfileCmd implements `ghsec profile <list|use|add|remove>`.
func runProfileCmd(_ context.Context, args []string) error {
	if len(args) == 0 {
		return usagef("profile: a subcommand is required (list, use, add, remove)\n\n%s", profileUsage)
	}

	sub := args[0]
	rest := args[1:]

	switch sub {
	case "list", "ls":
		return profileList(rest)
	case "use", "switch":
		return profileUse(rest)
	case "add":
		return profileAdd(rest)
	case "remove", "rm", "delete":
		return profileRemove(rest)
	case "-h", "--help", "help":
		fmt.Print(profileUsage)
		return errFlagHandled
	default:
		return usagef("profile: unknown subcommand %q (use list, use, add or remove)\n\n%s", sub, profileUsage)
	}
}

// loadConfigOrEmpty loads the config, treating "missing" as empty.
func loadConfigOrEmpty() (*config.Config, error) {
	cfg, err := config.Load()
	if err == nil {
		return cfg, nil
	}
	if errors.Is(err, config.ErrNoConfig) {
		return &config.Config{Profiles: map[string]config.Profile{}}, nil
	}
	return nil, fmt.Errorf("read configuration: %w", err)
}

// profileList prints stored profiles with masked tokens.
func profileList(args []string) error {
	fs := buildFlagSet("profile list")
	asJSON := fs.Bool("json", false, "print JSON on stdout")
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	cfg, err := loadConfigOrEmpty()
	if err != nil {
		return err
	}

	views := make([]profileView, 0, len(cfg.Profiles))
	for _, alias := range cfg.Aliases() {
		p := cfg.Profiles[alias]
		views = append(views, profileView{
			Alias:    alias,
			Username: p.Username,
			Token:    config.MaskToken(p.Token),
			Active:   alias == cfg.ActiveProfile,
		})
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(views)
	}

	if len(views) == 0 {
		fmt.Fprintln(os.Stdout, "no profiles configured")
		return nil
	}
	for _, v := range views {
		marker := " "
		if v.Active {
			marker = "*"
		}
		fmt.Fprintf(os.Stdout, "%s %-20s @%-20s %s\n", marker, v.Alias, v.Username, v.Token)
	}
	return nil
}

// profileUse activates a stored profile.
func profileUse(args []string) error {
	if len(args) != 1 {
		return usagef("profile use: exactly one alias is required\n\n%s", profileUsage)
	}
	alias := strings.TrimSpace(args[0])

	cfg, err := loadConfigOrEmpty()
	if err != nil {
		return err
	}
	if err := cfg.SetActive(alias); err != nil {
		return usagef("%v (available: %s)", err, strings.Join(cfg.Aliases(), ", "))
	}
	if err := cfg.Save(); err != nil {
		return fmt.Errorf("save configuration: %w", err)
	}
	fmt.Fprintf(os.Stdout, "active profile is now %q\n", alias)
	return nil
}

// profileAdd stores a new profile, optionally verifying the token first.
func profileAdd(args []string) error {
	fs := buildFlagSet("profile add")
	var alias, token string
	var noVerify bool
	var asJSON bool
	fs.StringVar(&alias, "alias", "", "alias for the new profile (default: the GitHub login)")
	fs.StringVar(&token, "token", "", "GitHub token (default: $GITHUB_TOKEN, or stdin)")
	fs.BoolVar(&noVerify, "no-verify", false, "store the token without calling GET /user")
	fs.BoolVar(&asJSON, "json", false, "print JSON on stdout")
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	if strings.TrimSpace(token) == "" {
		token = strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	}
	if strings.TrimSpace(token) == "" {
		if stdinIsTTY() {
			return usagef("profile add: pass --token, set GITHUB_TOKEN, or pipe the token on stdin")
		}
		raw, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<16))
		if err != nil {
			return fmt.Errorf("read the token from stdin: %w", err)
		}
		token = strings.TrimSpace(string(raw))
	}
	if token == "" {
		return usagef("profile add: the token is empty")
	}

	username := ""
	if !noVerify {
		client := api.NewClient(token)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		user, err := client.VerifyToken(ctx)
		if err != nil {
			return fmt.Errorf("%s: %w", api.FriendlyMessage(err, "verify the token"), err)
		}
		username = user.Login
	}

	if strings.TrimSpace(alias) == "" {
		if username == "" {
			return usagef("profile add: --alias is required when --no-verify is used")
		}
		alias = username
	}

	cfg, err := loadConfigOrEmpty()
	if err != nil {
		return err
	}
	if err := cfg.AddProfile(alias, config.Profile{Token: token, Username: username}); err != nil {
		return usagef("%v", err)
	}
	if err := cfg.SetActive(alias); err != nil {
		return fmt.Errorf("activate profile: %w", err)
	}
	if err := cfg.Save(); err != nil {
		return fmt.Errorf("save configuration: %w", err)
	}

	if asJSON {
		return json.NewEncoder(os.Stdout).Encode(profileView{
			Alias:    alias,
			Username: username,
			Token:    config.MaskToken(token),
			Active:   true,
		})
	}
	fmt.Fprintf(os.Stdout, "added profile %q (active)\n", alias)
	return nil
}

// profileRemove deletes a stored profile.
func profileRemove(args []string) error {
	if len(args) != 1 {
		return usagef("profile remove: exactly one alias is required\n\n%s", profileUsage)
	}
	alias := strings.TrimSpace(args[0])

	cfg, err := loadConfigOrEmpty()
	if err != nil {
		return err
	}
	if err := cfg.RemoveProfile(alias); err != nil {
		return usagef("%v", err)
	}
	if err := cfg.Save(); err != nil {
		return fmt.Errorf("save configuration: %w", err)
	}
	fmt.Fprintf(os.Stdout, "removed profile %q\n", alias)
	return nil
}

// errCancelled signals that the user declined to submit.
var errCancelled = errors.New("cancelled")

// firstNonEmpty returns the first non-blank value.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// Usage texts for the subcommands.
const reportUsage = `ghsec report — file a private vulnerability report

Usage:
  ghsec report --repo OWNER/REPO --summary TEXT (--description TEXT | --description-file PATH)
               [--severity critical|high|medium|low] [--cve CVE-YYYY-NNNN]
               [--token TOKEN | --profile ALIAS] [--api-url URL]
               [--yes] [--json] [--dry-run] [--timeout 60s]

Notes:
  * Never prompts when stdout is not a terminal: pass --yes to submit.
  * --description-file - reads the body from stdin.
  * GHSA ids and links are printed on stdout; diagnostics go to stderr.

Examples:
  ghsec report --repo acme/widget --summary "RCE in YAML loader" \
               --severity high --description-file advisory.md --yes

  echo "details..." | ghsec report --repo acme/widget --summary "SSRF" \
               --description-file - --yes --json
`

const advisoryUsage = `ghsec advisory — create a maintainer security advisory draft

Usage:
  ghsec advisory --repo OWNER/REPO --summary TEXT (--description TEXT | --description-file PATH)
                 [--severity critical|high|medium|low] [--cve CVE-YYYY-NNNN]
                 [--affected "<= 1.2.3"] [--token TOKEN | --profile ALIAS]
                 [--yes] [--json] [--dry-run] [--timeout 60s]

Notes:
  * Creates an unpublished draft you can review and publish on GitHub.
  * --affected is folded into the description as a "## Affected versions" section.

Examples:
  ghsec advisory --repo acme/widget --summary "YAML tag RCE" --severity critical \
                 --affected "<= 1.4.2" --description-file advisory.md --yes
`

const profileUsage = `ghsec profile — manage stored API keys

Usage:
  ghsec profile list [--json]
  ghsec profile use ALIAS
  ghsec profile add [--alias NAME] [--token TOKEN] [--no-verify] [--json]
  ghsec profile remove ALIAS

Notes:
  * Tokens are always printed masked.
  * "ghsec profile add" reads the token from --token, $GITHUB_TOKEN, or stdin.

Examples:
  echo "$GH_TOKEN" | ghsec profile add --alias work
  ghsec profile list
  ghsec profile use work
`

// cvePattern matches an official CVE identifier.
var cvePattern = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,}$`)

// validateCVE accepts an empty value or a well-formed CVE id.
func validateCVE(cve string) error {
	cve = strings.TrimSpace(cve)
	if cve == "" {
		return nil
	}
	if !cvePattern.MatchString(cve) {
		return usagef("--cve must look like CVE-2026-12345, got %q", cve)
	}
	return nil
}

// recordCLIHistory appends a successful CLI submission to the local history
// index so `ghsec history` can show it later. Failures are reported on stderr
// but never fail the submission, which already succeeded on GitHub.
func recordCLIHistory(kind config.SubmissionKind, owner, repo, summary, severity string, adv *api.Advisory) {
	if adv == nil {
		return
	}
	cfg, err := loadConfigOrEmpty()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not read the history index: %v\n", err)
		return
	}

	entry := config.Submission{
		Kind:     kind,
		Summary:  summary,
		Severity: severity,
		GHSAID:   adv.GHSAID,
		CVEID:    adv.CVEID,
		URL:      adv.HTMLURL,
		Alias:    cfg.ActiveProfile,
		// The repository is known from the command that submitted, so it is
		// passed in rather than guessed from a response URL. Guessing broke
		// whenever GitHub returned a URL whose shape differed from the
		// expected one, which left unrefreshable history entries.
		Owner: owner,
		Repo:  repo,
	}

	cfg.AddSubmission(entry)
	if err := cfg.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not record this submission locally: %v\n", err)
	}
}
