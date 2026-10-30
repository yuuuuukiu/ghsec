// Command ghsec is a terminal UI for reporting GitHub security vulnerabilities
// and managing repository security advisories.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mattn/go-isatty"

	"github.com/yuuuuukiu/ghsec/internal/api"
	"github.com/yuuuuukiu/ghsec/internal/config"
	"github.com/yuuuuukiu/ghsec/internal/editor"
	"github.com/yuuuuukiu/ghsec/internal/tui"
)

// Build metadata, injected via -ldflags at release time.
var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

// supportedFlags is the tiny CLI surface: ghsec is a TUI, so flags stay minimal.
const usageText = `ghsec — GitHub Security Advisories from your terminal

Usage:
  ghsec                          launch the interactive UI (TUI)
  ghsec report [flags]           file a private vulnerability report
  ghsec advisory [flags]         create a maintainer advisory draft
  ghsec list [flags]             list a repository's advisories and their status
  ghsec show [flags]             show one advisory in full
  ghsec edit [flags]             update an existing advisory
  ghsec comments <subcommand>    read and post replies on an advisory
  ghsec cve [flags]              request a CVE id for an advisory
  ghsec history <subcommand>     show what you submitted and its live status
  ghsec profile <subcommand>     manage stored API keys
  ghsec --version                print version information
  ghsec --help                   show this help

Run "ghsec <command> --help" for the flags of a subcommand.

Environment:
  GITHUB_TOKEN / GH_TOKEN    token used when --token is not given
  GITHUB_API_URL             API root for GitHub Enterprise Server
  GHSEC_CONFIG_HOME          override the configuration directory
  XDG_CONFIG_HOME            base for the config directory on Linux/macOS
  VISUAL / EDITOR            editor used for long-form vulnerability descriptions

Exit codes:
  0 success   1 runtime failure   2 invalid usage   130 interrupted

Docs: https://github.com/yuuuuukiu/ghsec`

// verifyTimeout bounds the token verification call.
const verifyTimeout = 30 * time.Second

// app carries the mutable state of a single ghsec run.
type app struct {
	cfg    *config.Config
	cfgErr error // non-fatal config load problem, surfaced once
	client *api.Client
	alias  string
	user   string
}

func main() {
	// Ctrl+C is handled explicitly so we can restore the terminal and exit
	// cleanly without ever leaving a half-written config behind.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx); err != nil {
		switch {
		case errors.Is(err, errFlagHandled):
			// --help / --version already produced their output.
		case errors.Is(err, errCancelled):
			fmt.Fprintln(os.Stderr, "cancelled: nothing was sent")
			os.Exit(exitOK)
		case errors.Is(err, tui.ErrAborted):
			fmt.Fprintln(os.Stderr, tui.Muted("Cancelled."))
			os.Exit(130)
		case isUsageError(err):
			// Invalid invocation: print the message and the relevant usage text.
			fmt.Fprintln(os.Stderr, "ghsec: "+err.Error())
			os.Exit(exitUsage)
		default:
			// Runtime failure. Plain text on stderr keeps CLI output parseable,
			// while the TUI path never reaches this branch.
			fmt.Fprintln(os.Stderr, "ghsec: "+err.Error())
			os.Exit(exitError)
		}
	}
}

// run is the whole program; it returns an error instead of exiting so tests and
// signal handling stay in one place.
func run(ctx context.Context) error {
	args := os.Args[1:]

	// No arguments: the interactive TUI, exactly as before.
	if len(args) == 0 {
		return runTUI(ctx)
	}

	// Any argument is either a subcommand or a flag. Global flags first, then
	// subcommands, so `ghsec --version`, `ghsec report ...` and `ghsec --help`
	// all behave predictably.
	switch args[0] {
	case "-h", "--help", "help":
		fmt.Print(usageText)
		return errFlagHandled
	case "-v", "--version", "version":
		fmt.Printf("ghsec %s (commit %s, built %s)\n", version, commit, buildDate)
		return errFlagHandled
	case "report":
		return runReportCmd(ctx, args[1:])
	case "advisory", "advisories":
		return runAdvisoryCmd(ctx, args[1:])
	case "list":
		return runListCmd(ctx, args[1:])
	case "show":
		return runShowCmd(ctx, args[1:])
	case "comments", "comment":
		return runCommentsCmd(ctx, args[1:])
	case "cve":
		return runCVECmd(ctx, args[1:])
	case "edit":
		return runEditCmd(ctx, args[1:])
	case "history":
		return runHistoryCmd(ctx, args[1:])
	case "profile", "profiles", "config":
		return runProfileCmd(ctx, args[1:])
	default:
		if strings.HasPrefix(args[0], "-") {
			return usagef("unknown flag %q\n\n%s", args[0], usageText)
		}
		return usagef("unknown command %q\n\n%s", args[0], usageText)
	}
}

// runTUI starts the interactive experience.
func runTUI(ctx context.Context) error {
	if !isatty.IsTerminal(os.Stdout.Fd()) && !isatty.IsCygwinTerminal(os.Stdout.Fd()) {
		return errors.New("ghsec needs an interactive terminal for the TUI; " +
			"use a subcommand such as `ghsec report --help` for non-interactive use")
	}

	fmt.Println(tui.Banner())
	fmt.Println()

	a := &app{}
	if err := a.loadConfig(); err != nil {
		return err
	}

	if err := a.ensureProfile(ctx); err != nil {
		return err
	}

	return a.loop(ctx)
}

// handleFlags implements the minimal non-interactive CLI surface.
//
// errFlagHandled signals that the requested action completed and the caller
// should exit successfully without starting the TUI.
func handleFlags(args []string) error {
	for _, arg := range args {
		switch arg {
		case "-h", "--help", "help":
			fmt.Println(usageText)
			return errFlagHandled
		case "-v", "--version", "version":
			fmt.Printf("ghsec %s (commit %s, built %s)\n", version, commit, buildDate)
			return errFlagHandled
		default:
			return fmt.Errorf("unknown argument %q\n\n%s", arg, usageText)
		}
	}
	return nil
}

// errFlagHandled short-circuits run() after --help/--version output.
var errFlagHandled = errors.New("flag handled")

// loadConfig loads the on-disk configuration, tolerating a missing file.
func (a *app) loadConfig() error {
	cfg, err := config.Load()
	switch {
	case err == nil:
		a.cfg = cfg
	case errors.Is(err, config.ErrNoConfig):
		// First run: start from an empty in-memory config. Nothing is written
		// until the user completes onboarding.
		a.cfg = &config.Config{Profiles: map[string]config.Profile{}}
	default:
		// A malformed file must not wedge the tool: keep the error, continue
		// with an empty config and let onboarding repair the situation.
		a.cfg = &config.Config{Profiles: map[string]config.Profile{}}
		a.cfgErr = err
	}
	return nil
}

// ensureProfile guarantees that we have a verified, active credential.
func (a *app) ensureProfile(ctx context.Context) error {
	if a.cfgErr != nil {
		fmt.Println(tui.WarnPanel("Configuration could not be read",
			a.cfgErr.Error()+"\n\nghsec will start fresh; completing onboarding overwrites the file."))
		fmt.Println()
	}

	if alias, profile, ok := a.cfg.Active(); ok && strings.TrimSpace(profile.Token) != "" {
		if err := a.verify(ctx, alias, profile); err != nil {
			// Stored token is dead: fall through to onboarding so the user can
			// fix it instead of hitting a wall.
			fmt.Println(tui.WarnPanel("Stored token was rejected", err.Error()))
			fmt.Println()
			return a.onboard(ctx)
		}
		return nil
	}
	return a.onboard(ctx)
}

// onboard runs the first-run (or repair) credential flow.
func (a *app) onboard(ctx context.Context) error {
	fmt.Println(tui.Header("Welcome to ghsec"))
	fmt.Println(tui.Muted("No usable GitHub token found. Let's set one up — it takes about a minute."))
	fmt.Println()

	for attempt := 1; attempt <= 3; attempt++ {
		input, err := tui.RunOnboarding()
		if err != nil {
			if errors.Is(err, tui.ErrAborted) {
				return tui.ErrAborted
			}
			return err
		}

		profile, verr := a.verifyToken(ctx, input.Token)
		if verr != nil {
			fmt.Println(tui.ErrorPanel("Token verification failed", verr.Error()))
			fmt.Println()
			if attempt == 3 {
				return errors.New("could not verify a GitHub token after 3 attempts")
			}
			continue
		}

		alias := strings.TrimSpace(input.Alias)
		if alias == "" {
			alias = profile.Username
		}
		if err := config.ValidateAlias(alias); err != nil {
			fmt.Println(tui.ErrorPanel("Invalid profile alias", err.Error()))
			fmt.Println()
			continue
		}

		if err := a.cfg.AddProfile(alias, profile); err != nil {
			fmt.Println(tui.ErrorPanel("Could not store profile", err.Error()))
			fmt.Println()
			continue
		}
		if err := a.cfg.SetActive(alias); err != nil {
			return err
		}
		if err := a.cfg.Save(); err != nil {
			return fmt.Errorf("save configuration: %w", err)
		}

		a.alias, a.user = alias, profile.Username
		a.client = api.NewClient(profile.Token)

		fmt.Println(tui.SuccessPanel("You're all set",
			tui.KeyValue("Profile", alias)+"\n"+
				tui.KeyValue("GitHub user", profile.Username)+"\n"+
				tui.KeyValue("Config file", mustPath())+"\n\n"+
				tui.Muted("Permissions are restricted to your user account (0600).")))
		fmt.Println()
		return nil
	}
	return errors.New("onboarding did not complete")
}

// verifyToken performs the network round-trip needed to bind a token to a login.
func (a *app) verifyToken(ctx context.Context, token string) (config.Profile, error) {
	client := api.NewClient(token)
	verifyCtx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()

	fmt.Println(tui.Muted("Verifying token with GitHub…"))
	user, err := client.VerifyToken(verifyCtx)
	if err != nil {
		return config.Profile{}, errors.New(api.FriendlyMessage(err, "verify the token"))
	}
	return config.Profile{Token: strings.TrimSpace(token), Username: user.Login}, nil
}

// verify checks a stored profile and refreshes the client.
func (a *app) verify(ctx context.Context, alias string, profile config.Profile) error {
	client := api.NewClient(profile.Token)
	verifyCtx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()

	user, err := client.VerifyToken(verifyCtx)
	if err != nil {
		return errors.New(api.FriendlyMessage(err, "verify the stored token"))
	}

	a.client = client
	a.alias = alias
	a.user = user.Login

	if user.Login != profile.Username {
		// Keep the cached login in sync when the token was rotated externally.
		if p, ok := a.cfg.Profiles[alias]; ok {
			p.Username = user.Login
			a.cfg.Profiles[alias] = p
			if err := a.cfg.Save(); err != nil {
				fmt.Println(tui.Warnf("Could not refresh cached username: %v", err))
			}
		}
	}
	return nil
}

// loop is the main menu loop.
func (a *app) loop(ctx context.Context) error {
	for {
		action, err := tui.RunMainMenu(a.alias, a.user)
		if err != nil {
			if errors.Is(err, tui.ErrAborted) {
				fmt.Println(tui.Muted("Goodbye."))
				return nil
			}
			return err
		}

		switch action {
		case tui.ActionQuit:
			fmt.Println(tui.Muted("Goodbye."))
			return nil
		case tui.ActionReport:
			a.privateReport(ctx)
		case tui.ActionAdvisory:
			a.advisoryDraft(ctx)
		case tui.ActionBrowse:
			if err := a.browse(ctx); err != nil {
				if errors.Is(err, tui.ErrAborted) {
					continue
				}
				return err
			}
		case tui.ActionProfiles:
			if err := a.profileManager(ctx); err != nil {
				if errors.Is(err, tui.ErrAborted) {
					continue
				}
				return err
			}
		}

		if ctx.Err() != nil {
			fmt.Println(tui.Muted("Interrupted. Goodbye."))
			return nil
		}
	}
}

// privateReport implements business flow A.
func (a *app) privateReport(ctx context.Context) {
	fmt.Println()
	fmt.Println(tui.Header("Private vulnerability report"))
	fmt.Println(tui.Muted("Filed against a repository that has private vulnerability reporting enabled."))
	fmt.Println()

	input, err := tui.RunPrivateReportForm("")
	if err != nil {
		a.reportFlowErr("report", err)
		return
	}

	// Pre-flight: if the repository plainly does not accept private reports,
	// warn now rather than letting GitHub answer with an opaque 403 later.
	a.warnIfReportingDisabled(ctx, input.Repo)

	desc, ok := a.collectDescription(input.Description)
	if !ok {
		return
	}
	input.Description = desc

	if !a.confirmReport("private vulnerability report", input.Repo, input.Summary, input.Severity, input.CVEID, input.Description) {
		return
	}

	callCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	fmt.Println(tui.Muted("Submitting to GitHub…"))
	advisory, err := a.client.SubmitPrivateReport(callCtx, ownerOf(input.Repo), repoOf(input.Repo), api.PrivateReportRequest{
		Summary:     input.Summary,
		Description: input.Description,
		Severity:    input.Severity,
		CVEID:       input.CVEID,
	})
	if err != nil {
		fmt.Println(tui.ErrorPanel("Report was not submitted", api.FriendlyMessage(err, "submit the private report")))
		fmt.Println()
		return
	}

	a.recordSubmission(config.KindReport, input.Repo, input.Summary, string(input.Severity), input.CVEID, advisory)

	fmt.Println()
	fmt.Println(tui.SuccessCardForRepo(advisory, input.Repo))
	fmt.Println()
}

// advisoryDraft implements business flow B.
func (a *app) advisoryDraft(ctx context.Context) {
	fmt.Println()
	fmt.Println(tui.Header("Maintainer security advisory draft"))
	fmt.Println(tui.Muted("Creates a draft advisory you can edit and publish from the repository's Security tab."))
	fmt.Println()

	input, err := tui.RunAdvisoryForm("")
	if err != nil {
		a.reportFlowErr("advisory", err)
		return
	}

	desc, ok := a.collectDescription(input.Description)
	if !ok {
		return
	}
	input.Description = desc

	if !a.confirmAdvisory(input) {
		return
	}

	callCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	fmt.Println(tui.Muted("Creating draft…"))
	advisory, err := a.client.CreateAdvisoryDraft(callCtx, ownerOf(input.Repo), repoOf(input.Repo), api.AdvisoryDraftRequest{
		Summary:      input.Summary,
		Description:  input.Description,
		Severity:     input.Severity,
		CVEID:        input.CVEID,
		AffectedText: input.Affected,
	})
	if err != nil {
		fmt.Println(tui.ErrorPanel("Draft was not created", api.FriendlyMessage(err, "create the advisory draft")))
		fmt.Println()
		return
	}

	a.recordSubmission(config.KindAdvisory, input.Repo, input.Summary, string(input.Severity), input.CVEID, advisory)

	fmt.Println()
	fmt.Println(tui.SuccessCardForRepo(advisory, input.Repo))
	fmt.Println()
}

// warnIfReportingDisabled checks whether a repository accepts private
// vulnerability reports and prints an actionable warning when it does not.
//
// This is a courtesy check only: the lookup is best effort, so any failure
// (bad repo, no permission, network) is ignored and the submission proceeds
// exactly as it would have without the hint.
func (a *app) warnIfReportingDisabled(ctx context.Context, repoSpec string) {
	owner, repo := ownerOf(repoSpec), repoOf(repoSpec)
	if owner == "" || repo == "" || a.client == nil {
		return
	}

	probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	fmt.Println(tui.Muted("Checking whether " + repoSpec + " accepts private reports…"))
	repository, err := a.client.GetRepository(probeCtx, owner, repo)
	switch {
	case err != nil:
		// Deliberately silent: the pre-flight must not obstruct the main task.
		return
	case repository.AdvisoryEnabled:
		fmt.Println(tui.Successf("✓ %s accepts private vulnerability reports.", repoSpec))
	default:
		fmt.Println(tui.WarnPanel("Private reporting looks disabled",
			fmt.Sprintf("GitHub reports that %s does not currently accept private vulnerability reports.\n", repoSpec)+
				tui.Muted("A maintainer must enable it in Settings → Code security → Private vulnerability reporting.\n"+
					"You can still submit — GitHub will be the final judge.")))
	}
	fmt.Println()
}

// collectDescription gives the user a chance to replace the inline description
// with content read from a file or produced in their editor.
func (a *app) collectDescription(inline string) (string, bool) {
	source, err := tui.RunDescriptionSource()
	if err != nil {
		a.reportFlowErr("description", err)
		return "", false
	}

	switch source {
	case tui.SourceInline:
		return inline, true

	case tui.SourceFile:
		path, err := tui.RunTextInput("Description file", "Path to a local Markdown or text file (~ is expanded).", "~/vuln-report.md", nil)
		if err != nil {
			a.reportFlowErr("description", err)
			return "", false
		}
		content, rerr := editor.ReadFile(path)
		if rerr != nil {
			fmt.Println(tui.ErrorPanel("Could not read that file", rerr.Error()))
			fmt.Println()
			return "", false
		}
		return content, true

	case tui.SourceEditor:
		fmt.Println(tui.Muted("Opening " + editor.ResolveEditor().Name + ". Save and close the file to continue."))
		content, eerr := editor.Open(inline)
		if eerr != nil {
			// The editor may still have produced usable content.
			if strings.TrimSpace(content) == "" {
				fmt.Println(tui.ErrorPanel("Editor failed", eerr.Error()))
				fmt.Println()
				return "", false
			}
			fmt.Println(tui.Warnf("%v", eerr))
		}
		if strings.TrimSpace(content) == "" {
			fmt.Println(tui.WarnPanel("Empty description", "The editor returned no content, so nothing was submitted."))
			fmt.Println()
			return "", false
		}
		return content, true

	default:
		return inline, true
	}
}

// confirmReport renders the Markdown preview and asks for explicit consent.
func (a *app) confirmReport(kind, repo, summary string, sev api.Severity, cve, desc string) bool {
	fmt.Println()
	body := tui.KeyValue("Repository", repo) + "\n" +
		tui.KeyValue("Summary", summary) + "\n" +
		tui.KeyValue("Severity", tui.SeverityBadge(sev)) + "\n"
	if strings.TrimSpace(cve) != "" {
		body += tui.KeyValue("CVE", cve) + "\n"
	}
	body += "\n" + tui.PreviewPanel("Description preview", desc, 88)
	fmt.Println(tui.InfoPanel("Review the "+kind, body))
	fmt.Println()

	ok, err := tui.RunConfirm(fmt.Sprintf("Submit this %s to %s?", kind, repo), false)
	if err != nil || !ok {
		fmt.Println(tui.Muted("Cancelled — nothing was sent."))
		fmt.Println()
		return false
	}
	return true
}

// confirmAdvisory previews a draft, including affected version ranges.
func (a *app) confirmAdvisory(in *tui.AdvisorInput) bool {
	fmt.Println()
	body := tui.KeyValue("Repository", in.Repo) + "\n" +
		tui.KeyValue("Summary", in.Summary) + "\n" +
		tui.KeyValue("Severity", tui.SeverityBadge(in.Severity)) + "\n"
	if strings.TrimSpace(in.CVEID) != "" {
		body += tui.KeyValue("CVE", in.CVEID) + "\n"
	}
	if strings.TrimSpace(in.Affected) != "" {
		body += tui.KeyValue("Affected", strings.ReplaceAll(strings.TrimSpace(in.Affected), "\n", "; ")) + "\n"
	}
	body += "\n" + tui.PreviewPanel("Description preview", in.Description, 88)
	fmt.Println(tui.InfoPanel("Review the advisory draft", body))
	fmt.Println()

	ok, err := tui.RunConfirm(fmt.Sprintf("Create this draft advisory in %s?", in.Repo), false)
	if err != nil || !ok {
		fmt.Println(tui.Muted("Cancelled — nothing was sent."))
		fmt.Println()
		return false
	}
	return true
}

// reportFlowErr distinguishes a user cancellation from a real failure.
func (a *app) reportFlowErr(stage string, err error) {
	if errors.Is(err, tui.ErrAborted) {
		fmt.Println(tui.Muted("Cancelled."))
		fmt.Println()
		return
	}
	fmt.Println(tui.ErrorPanel("Could not collect the "+stage, err.Error()))
	fmt.Println()
}

// recordSubmission appends a successful submission to the local history index.
//
// GitHub's REST API has no "list the reports I filed" endpoint, so this local
// index is the only way to offer a submission history. Only identifiers are
// stored; status is always re-read from GitHub.
func (a *app) recordSubmission(kind config.SubmissionKind, repoSpec, summary, severity, cve string, adv *api.Advisory) {
	if a.cfg == nil {
		return
	}

	entry := config.Submission{
		Kind:     kind,
		Owner:    ownerOf(repoSpec),
		Repo:     repoOf(repoSpec),
		Summary:  summary,
		Severity: severity,
		CVEID:    cve,
		Alias:    a.alias,
	}
	if adv != nil {
		entry.GHSAID = adv.GHSAID
		entry.URL = adv.HTMLURL
		if entry.CVEID == "" {
			entry.CVEID = adv.CVEID
		}
	}

	a.cfg.AddSubmission(entry)
	if err := a.cfg.Save(); err != nil {
		fmt.Println(tui.Warnf("Could not record this submission locally: %v", err))
	}
}

// browse is the entry point for the "Browse advisories" menu item.
//
// GitHub scopes advisories to a repository, and the API offers no
// "all repositories I can see" listing, so the flow starts by asking which
// repository to inspect.
func (a *app) browse(ctx context.Context) error {
	fmt.Println()
	fmt.Println(tui.Header("Browse security advisories"))
	fmt.Println(tui.Muted("Review submitted reports, their status, CVE progress and replies."))
	fmt.Println()

	repoSpec, err := tui.RunRepoInput("")
	if err != nil {
		if errors.Is(err, tui.ErrAborted) {
			return nil // backing out of the prompt is not an app-level abort
		}
		return err
	}

	owner, repo, err := api.ValidateRepoSpec(repoSpec)
	if err != nil {
		fmt.Println(tui.ErrorPanel("Invalid repository", err.Error()))
		fmt.Println()
		return nil
	}
	if a.client == nil {
		fmt.Println(tui.ErrorPanel("Not signed in", "Configure an API key from the profiles menu first."))
		fmt.Println()
		return nil
	}

	if err := tui.BrowseAdvisories(ctx, a.client, owner, repo); err != nil {
		if errors.Is(err, tui.ErrAborted) {
			return nil
		}
		return err
	}
	return nil
}

// profileManager implements menu option 3.
func (a *app) profileManager(ctx context.Context) error {
	for {
		fmt.Println()
		fmt.Println(tui.Header("API keys & profiles"))
		fmt.Println(a.profileTable())
		fmt.Println()

		action, err := tui.RunProfileMenu(a.cfg.Aliases(), a.alias)
		if err != nil {
			return err
		}

		switch action {
		case tui.ProfBack:
			return nil
		case tui.ProfSwitch:
			if err := a.switchProfile(ctx); err != nil {
				return err
			}
		case tui.ProfAdd:
			if err := a.addProfile(ctx); err != nil {
				return err
			}
		case tui.ProfDelete:
			if err := a.deleteProfile(); err != nil {
				return err
			}
		}
	}
}

// profileTable renders every stored profile with a masked token.
func (a *app) profileTable() string {
	aliases := a.cfg.Aliases()
	if len(aliases) == 0 {
		return tui.Muted("No profiles configured.")
	}
	var b strings.Builder
	for _, alias := range aliases {
		p := a.cfg.Profiles[alias]
		marker := "  "
		if alias == a.cfg.ActiveProfile {
			marker = tui.Badge("active")
		}
		b.WriteString(marker + " " +
			tui.Accent(alias) + "  " +
			tui.Muted("@"+p.Username) + "  " +
			config.MaskToken(p.Token) + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// switchProfile verifies and activates another stored profile.
func (a *app) switchProfile(ctx context.Context) error {
	aliases := a.cfg.Aliases()
	if len(aliases) < 2 {
		fmt.Println(tui.InfoPanel("Nothing to switch to", "Only one profile is configured. Add another key first."))
		return nil
	}

	choice, err := tui.RunProfilePicker(aliases, a.cfg.ActiveProfile)
	if err != nil {
		return err
	}
	if choice == a.cfg.ActiveProfile {
		fmt.Println(tui.Muted("That profile is already active."))
		return nil
	}

	profile, ok := a.cfg.Profiles[choice]
	if !ok {
		return fmt.Errorf("profile %q disappeared", choice)
	}
	if err := a.verify(ctx, choice, profile); err != nil {
		fmt.Println(tui.ErrorPanel("Could not switch profile", err.Error()))
		return nil
	}
	if err := a.cfg.SetActive(choice); err != nil {
		return err
	}
	if err := a.cfg.Save(); err != nil {
		return fmt.Errorf("save configuration: %w", err)
	}
	fmt.Println(tui.SuccessPanel("Profile switched", tui.KeyValue("Now using", choice)+"\n"+tui.KeyValue("Signed in as", a.user)))
	return nil
}

// addProfile runs the onboarding flow again for an additional credential.
func (a *app) addProfile(ctx context.Context) error {
	fmt.Println()
	fmt.Println(tui.Header("Add a new API key"))

	input, err := tui.RunTokenPrompt()
	if err != nil {
		return err
	}

	profile, verr := a.verifyToken(ctx, input.Token)
	if verr != nil {
		fmt.Println(tui.ErrorPanel("Token verification failed", verr.Error()))
		return nil
	}

	alias := strings.TrimSpace(input.Alias)
	if alias == "" {
		alias = profile.Username
	}
	if err := config.ValidateAlias(alias); err != nil {
		fmt.Println(tui.ErrorPanel("Invalid alias", err.Error()))
		return nil
	}
	// Replacing an existing alias would silently drop its token, so confirm.
	if _, exists := a.cfg.Profiles[alias]; exists {
		ok, cerr := tui.RunConfirm(fmt.Sprintf("Profile %q already exists. Replace its token?", alias), false)
		if cerr != nil {
			return cerr
		}
		if !ok {
			fmt.Println(tui.Muted("Nothing changed."))
			return nil
		}
	}

	if err := a.cfg.AddProfile(alias, profile); err != nil {
		fmt.Println(tui.ErrorPanel("Could not add profile", err.Error()))
		return nil
	}
	if err := a.cfg.Save(); err != nil {
		return fmt.Errorf("save configuration: %w", err)
	}
	fmt.Println(tui.SuccessPanel("Profile added", tui.KeyValue("Alias", alias)+"\n"+tui.KeyValue("GitHub user", profile.Username)))
	return nil
}

// deleteProfile removes a stored credential after explicit confirmation.
func (a *app) deleteProfile() error {
	aliases := a.cfg.Aliases()
	if len(aliases) == 0 {
		fmt.Println(tui.Muted("No profiles to delete."))
		return nil
	}

	choice, err := tui.RunProfilePicker(aliases, a.cfg.ActiveProfile)
	if err != nil {
		return err
	}
	ok, cerr := tui.RunConfirm(fmt.Sprintf("Delete profile %q? This cannot be undone.", choice), false)
	if cerr != nil {
		return cerr
	}
	if !ok {
		fmt.Println(tui.Muted("Nothing was deleted."))
		return nil
	}

	if err := a.cfg.RemoveProfile(choice); err != nil {
		fmt.Println(tui.ErrorPanel("Could not delete profile", err.Error()))
		return nil
	}
	if err := a.cfg.Save(); err != nil {
		return fmt.Errorf("save configuration: %w", err)
	}

	// Re-point the runtime state if the active profile changed.
	if alias, profile, aok := a.cfg.Active(); aok {
		a.alias, a.user = alias, profile.Username
		a.client = api.NewClient(profile.Token)
	}
	fmt.Println(tui.SuccessPanel("Profile deleted", tui.KeyValue("Removed", choice)))
	return nil
}

// ownerOf splits an owner/repo spec, tolerating malformed input (which the
// form already validated) by returning the whole string as the owner.
func ownerOf(spec string) string {
	if i := strings.Index(spec, "/"); i > 0 {
		return spec[:i]
	}
	return spec
}

// repoOf returns the repository half of an owner/repo spec.
func repoOf(spec string) string {
	if i := strings.Index(spec, "/"); i > 0 && i+1 < len(spec) {
		return spec[i+1:]
	}
	return ""
}

// mustPath returns the config path or a placeholder, for display only.
func mustPath() string {
	path, err := config.Path()
	if err != nil {
		return "(unavailable)"
	}
	return path
}
