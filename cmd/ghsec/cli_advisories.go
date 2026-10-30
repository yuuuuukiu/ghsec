package main

// This file implements the read, edit and collaboration commands:
//
//	ghsec list                       list a repository's advisories
//	ghsec show                       render one advisory in full
//	ghsec comments <list|add|update> read and reply to the advisory thread
//	ghsec cve                        request a CVE id for an advisory
//	ghsec edit                       mutate an existing advisory
//
// They follow the same rules as cli.go: stdout carries data (one row per
// advisory, a rendered detail block, or --json), stderr carries diagnostics,
// usage mistakes return a usageError so main exits 2, credentials resolve
// through clientFlags, and nothing panics or calls os.Exit.
//
// Every command that targets one advisory shares the --repo/--ghsa/--json and
// credential flags through advisoryTarget, so the target validation lives in
// exactly one place.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/yukiu/ghsec/internal/api"
	"github.com/yukiu/ghsec/internal/editor"
)

// Limits shared by the paged read commands.
const (
	// maxPageSize is GitHub's maximum per_page value.
	maxPageSize = 100
	// defaultListLimit is how many advisories `ghsec list` fetches by default.
	defaultListLimit = 20
	// defaultCommentLimit is how many comments `ghsec comments list` fetches.
	defaultCommentLimit = 30
	// listSummaryWidth bounds the summary column of `ghsec list`, in runes.
	listSummaryWidth = 70
	// maxSummaryLen mirrors GitHub's advisory summary limit.
	maxSummaryLen = 256
)

// cwePattern matches an official CWE identifier.
var cwePattern = regexp.MustCompile(`(?i)^CWE-\d+$`)

// listUsage is the help text for `ghsec list`.
const listUsage = `ghsec list — list repository security advisories

Usage:
  ghsec list --repo OWNER/REPO [--state triage|draft|published|closed]
             [--sort created|updated|published] [--limit N] [--page N]
             [--token TOKEN | --profile ALIAS] [--api-url URL] [--json]

Notes:
  * Prints one line per advisory: state, severity, GHSA id, CVE id, summary.
  * Paging is handled for you; up to --limit advisories (1-100, default 20)
    are fetched, starting at --page (default 1).
  * An empty result is not an error: "no advisories found" is printed.
  * --json prints the AdvisoryDetail array as JSON on stdout.

Examples:
  ghsec list --repo acme/widget
  ghsec list --repo acme/widget --state published --limit 5 --json
`

// showUsage is the help text for `ghsec show`.
const showUsage = `ghsec show — show one security advisory in full

Usage:
  ghsec show --repo OWNER/REPO --ghsa GHSA-xxxx-yyyy-zzzz
             [--token TOKEN | --profile ALIAS] [--api-url URL] [--json]

Notes:
  * Renders the advisory header fields, then the description body verbatim.
  * A CVE id is shown as "not assigned" when GitHub has not issued one yet.
  * --json prints the raw AdvisoryDetail object on stdout.

Examples:
  ghsec show --repo acme/widget --ghsa GHSA-8f24-9j4g-6v7q
  ghsec show --repo acme/widget --ghsa GHSA-8f24-9j4g-6v7q --json
`

// commentsUsage is the help text for `ghsec comments`.
const commentsUsage = `ghsec comments — read and write repository advisory comments

Usage:
  ghsec comments list   --repo OWNER/REPO --ghsa GHSA-xxxx-yyyy-zzzz [--limit N] [--json]
  ghsec comments add    --repo OWNER/REPO --ghsa GHSA-xxxx-yyyy-zzzz
                        (--body TEXT | --body-file PATH)
  ghsec comments update --repo OWNER/REPO --ghsa GHSA-xxxx-yyyy-zzzz --comment-id N
                        (--body TEXT | --body-file PATH)

Notes:
  * --body-file - reads the body from stdin.
  * The body must not be empty; --body and --body-file are mutually exclusive.
  * Comments are visible to everyone who can see the advisory, so never paste
    secrets or unredacted credentials into the thread.

Examples:
  ghsec comments list --repo acme/widget --ghsa GHSA-8f24-9j4g-6v7q
  ghsec comments add --repo acme/widget --ghsa GHSA-8f24-9j4g-6v7q --body "Fixed in v1.2.3"
  ghsec comments update --repo acme/widget --ghsa GHSA-8f24-9j4g-6v7q \
                        --comment-id 123456 --body-file reply.md
`

// cveUsage is the help text for `ghsec cve`.
const cveUsage = `ghsec cve — request a CVE id for an advisory

Usage:
  ghsec cve --repo OWNER/REPO --ghsa GHSA-xxxx-yyyy-zzzz
            [--token TOKEN | --profile ALIAS] [--api-url URL] [--json]

Notes:
  * GitHub queues the request and assigns the CVE id asynchronously: the API
    answers 202 with no id, so re-run ` + "`ghsec show`" + ` later to read the id.
  * --json prints {"ok":true,"ghsa_id":"...","requested":true}.

Examples:
  ghsec cve --repo acme/widget --ghsa GHSA-8f24-9j4g-6v7q
  ghsec cve --repo acme/widget --ghsa GHSA-8f24-9j4g-6v7q --json
`

// editUsage is the help text for `ghsec edit`.
const editUsage = `ghsec edit — update an existing security advisory

Usage:
  ghsec edit --repo OWNER/REPO --ghsa GHSA-xxxx-yyyy-zzzz [flags]

Change at least one of:
  --summary TEXT             replace the one-line summary
  --description TEXT         replace the description inline
  --description-file PATH    replace the description from a file, or - for stdin
  --severity LEVEL           critical, high, medium or low
  --cve CVE-YYYY-NNNN        set or replace the CVE id; --cve "" clears it
  --state draft|published|closed
                             move the advisory to another state (triage is not
                             settable: GitHub does not allow moving back)
  --cvss-vector VECTOR       set the CVSS vector; --cvss-vector "" clears it
  --cwe-ids "CWE-79,CWE-89"  set the CWE list; --cwe-ids "" clears it

Output:
  --dry-run                  print the JSON patch on stdout without calling GitHub
  --json                     print the updated advisory as JSON on stdout

Notes:
  * Only the flags you actually pass are sent, so an edit never resets a field.
  * Empty strings are meaningful for --cve, --cvss-vector and --cwe-ids: they
    clear the field instead of leaving it untouched.

Examples:
  ghsec edit --repo acme/widget --ghsa GHSA-8f24-9j4g-6v7q --severity critical
  ghsec edit --repo acme/widget --ghsa GHSA-8f24-9j4g-6v7q --cve "" --state published
  ghsec edit --repo acme/widget --ghsa GHSA-8f24-9j4g-6v7q --summary "RCE in YAML" --dry-run
`

// repoGHSA is a validated (owner, repo, advisory id) triple.
type repoGHSA struct {
	owner string
	repo  string
	ghsa  string
}

// resolveRepoGHSA validates the shared --repo and --ghsa flags. It never touches
// the network: callers resolve credentials only after every input is checked.
func resolveRepoGHSA(repoFlag, ghsaFlag string) (repoGHSA, error) {
	if strings.TrimSpace(repoFlag) == "" {
		return repoGHSA{}, usagef("--repo is required: pass owner/repo")
	}
	owner, repo, err := api.ValidateRepoSpec(repoFlag)
	if err != nil {
		return repoGHSA{}, usagef("%v", err)
	}
	ghsa, err := normalizeGHSA(ghsaFlag)
	if err != nil {
		return repoGHSA{}, err
	}
	return repoGHSA{owner: owner, repo: repo, ghsa: ghsa}, nil
}

// normalizeGHSA upper-cases and sanity-checks a GHSA identifier.
//
// The check is deliberately structural (prefix plus a dash-separated body)
// rather than pinned to the current 4-4-4 layout, so older ids keep working.
func normalizeGHSA(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", usagef("--ghsa is required: pass the advisory id, for example GHSA-xxxx-yyyy-zzzz")
	}
	// Delegate to the api package so the CLI, the TUI and the client all agree
	// on one canonical form (GHSA- prefix plus a lower-case suffix, which is
	// what GitHub itself returns). A malformed id is a usage mistake, not a
	// runtime failure, so it is reported as such.
	if err := api.ValidateGHSAID(trimmed); err != nil {
		return "", usagef("--ghsa %v", err)
	}
	const prefix = "GHSA-"
	return prefix + strings.ToLower(trimmed[len(prefix):]), nil
}

// collectPages drains a paginated endpoint until limit items were gathered, the
// server reports no further page, or a page comes back empty. The request size
// is capped at maxPageSize, so a large --limit is still served by valid calls.
func collectPages[T any](fetch func(page, perPage int) (api.ListPage[T], error), startPage, limit int) ([]T, error) {
	items := make([]T, 0, limit)
	if limit <= 0 {
		return items, nil
	}
	page := startPage
	if page < 1 {
		page = 1
	}

	for len(items) < limit {
		perPage := limit - len(items)
		if perPage > maxPageSize {
			perPage = maxPageSize
		}

		result, err := fetch(page, perPage)
		if err != nil {
			return nil, err
		}
		items = append(items, result.Items...)

		if len(items) >= limit || len(result.Items) == 0 {
			break
		}

		next := result.NextPage
		if next <= 0 {
			if !result.HasMore {
				break
			}
			next = page + 1
		}
		if next == page {
			// Defensive: a server that keeps advertising the same page must not
			// spin this loop forever.
			break
		}
		page = next
	}

	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

// writeJSON emits v on w as JSON, indented unless compact is requested.
func writeJSON(w io.Writer, v any, compact bool) error {
	enc := json.NewEncoder(w)
	if !compact {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(v)
}

// advisoryTarget holds the flags shared by every command that addresses one
// advisory.
type advisoryTarget struct {
	clientFlags

	repo   string
	ghsa   string
	asJSON bool
}

// register adds the shared target, credential and output flags.
func (t *advisoryTarget) register(fs *flag.FlagSet) {
	t.clientFlags.register(fs)
	fs.StringVar(&t.repo, "repo", "", "target repository as owner/repo (required)")
	fs.StringVar(&t.ghsa, "ghsa", "", "advisory identifier, for example GHSA-xxxx-yyyy-zzzz (required)")
	fs.BoolVar(&t.asJSON, "json", false, "print machine-readable JSON on stdout")
}

// target validates --repo/--ghsa without resolving credentials.
func (t *advisoryTarget) target() (repoGHSA, error) {
	return resolveRepoGHSA(t.repo, t.ghsa)
}

// client resolves the credential flags into an API client.
func (t *advisoryTarget) client() (*api.Client, error) {
	client, _, err := t.clientFlags.resolve()
	if err != nil {
		return nil, err
	}
	return client, nil
}

// displayState renders an advisory state for humans ("Draft"), tolerating
// unrecognised values.
func displayState(raw string) string {
	state := api.AdvisoryState(strings.ToLower(strings.TrimSpace(raw)))
	if state.Valid() {
		return state.Label()
	}
	return firstNonEmpty(strings.TrimSpace(raw), "-")
}

// displaySeverity renders a severity for humans ("High"), tolerating unknown
// values.
func displaySeverity(raw string) string {
	sev := api.Severity(strings.ToLower(strings.TrimSpace(raw)))
	if sev.Valid() {
		return api.SeverityLabel(sev)
	}
	return firstNonEmpty(strings.TrimSpace(raw), "-")
}

// truncateRunes shortens s to at most max runes, marking the cut with an ellipsis.
func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max-1]) + "…"
}

// listFlags are the inputs for `ghsec list`.
type listFlags struct {
	clientFlags

	repo   string
	state  string
	sortBy string
	limit  int
	page   int
	asJSON bool
}

// register adds the list flags.
func (l *listFlags) register(fs *flag.FlagSet) {
	l.clientFlags.register(fs)
	fs.StringVar(&l.repo, "repo", "", "target repository as owner/repo (required)")
	fs.StringVar(&l.state, "state", "", "only list advisories in this state: triage, draft, published or closed")
	fs.StringVar(&l.sortBy, "sort", "created", "sort order: created, updated or published")
	fs.IntVar(&l.limit, "limit", defaultListLimit, "maximum number of advisories to print (1-100)")
	fs.IntVar(&l.page, "page", 1, "first page to fetch (1-based)")
	fs.BoolVar(&l.asJSON, "json", false, "print machine-readable JSON on stdout")
}

// validate checks the list inputs and builds the API options.
func (l *listFlags) validate() (owner, repo string, opts api.AdvisoryListOptions, limit int, err error) {
	if strings.TrimSpace(l.repo) == "" {
		return "", "", opts, 0, usagef("--repo is required: pass owner/repo")
	}
	owner, repo, err = api.ValidateRepoSpec(l.repo)
	if err != nil {
		return "", "", opts, 0, usagef("%v", err)
	}

	var state api.AdvisoryState
	if raw := strings.TrimSpace(l.state); raw != "" {
		state, err = api.ParseAdvisoryState(raw)
		if err != nil {
			return "", "", opts, 0, usagef("%v", err)
		}
	}

	sortBy := strings.ToLower(strings.TrimSpace(l.sortBy))
	switch sortBy {
	case "created", "updated", "published":
	case "":
		sortBy = "created"
	default:
		return "", "", opts, 0, usagef("--sort must be one of created, updated or published (got %q)", l.sortBy)
	}

	if l.limit < 1 || l.limit > maxPageSize {
		return "", "", opts, 0, usagef("--limit must be between 1 and %d (got %d)", maxPageSize, l.limit)
	}
	if l.page < 1 {
		return "", "", opts, 0, usagef("--page must be 1 or greater (got %d)", l.page)
	}

	return owner, repo, api.AdvisoryListOptions{State: state, Sort: sortBy, Page: l.page}, l.limit, nil
}

// runListCmd implements `ghsec list`.
func runListCmd(ctx context.Context, args []string) error {
	var f listFlags
	fs := buildFlagSet("list")
	f.register(fs)
	fs.Usage = func() { fmt.Fprint(os.Stderr, listUsage) }
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	owner, repo, opts, limit, err := f.validate()
	if err != nil {
		return err
	}

	client, _, err := f.clientFlags.resolve()
	if err != nil {
		return err
	}

	items, err := collectPages(func(page, perPage int) (api.ListPage[api.AdvisoryDetail], error) {
		pageOpts := opts
		pageOpts.Page = page
		pageOpts.PerPage = perPage
		return client.ListAdvisories(ctx, owner, repo, pageOpts)
	}, opts.Page, limit)
	if err != nil {
		return fmt.Errorf("%s: %w", api.FriendlyMessage(err, "list the security advisories"), err)
	}

	if f.asJSON {
		return writeJSON(os.Stdout, items, false)
	}
	if len(items) == 0 {
		fmt.Fprintln(os.Stdout, "no advisories found")
		return nil
	}
	for i := range items {
		printAdvisoryLine(os.Stdout, &items[i])
	}
	return nil
}

// printAdvisoryLine writes one row of the `ghsec list` table.
func printAdvisoryLine(w io.Writer, a *api.AdvisoryDetail) {
	if a == nil {
		return
	}

	state := displayState(a.State)

	severity := "-"
	if sev := api.Severity(strings.ToLower(strings.TrimSpace(a.Severity))); sev.Valid() {
		severity = api.SeverityLabel(sev)
	}

	id := strings.TrimSpace(a.GHSAID)
	if id == "" {
		id = a.Identifier()
	}

	cve := strings.TrimSpace(a.CVEID)
	if cve == "" {
		cve = "-"
	}

	summary := strings.TrimSpace(a.Summary)
	if summary == "" {
		summary = "-"
	}
	summary = truncateRunes(summary, listSummaryWidth)

	fmt.Fprintf(w, "%-9s  %-8s  %-19s  %-15s  %s\n", state, severity, id, cve, summary)
}

// runShowCmd implements `ghsec show`.
func runShowCmd(ctx context.Context, args []string) error {
	var t advisoryTarget
	fs := buildFlagSet("show")
	t.register(fs)
	fs.Usage = func() { fmt.Fprint(os.Stderr, showUsage) }
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	target, err := t.target()
	if err != nil {
		return err
	}

	client, err := t.client()
	if err != nil {
		return err
	}

	advisory, err := client.GetAdvisory(ctx, target.owner, target.repo, target.ghsa)
	if err != nil {
		return fmt.Errorf("%s: %w", api.FriendlyMessage(err, "fetch the advisory"), err)
	}

	if t.asJSON {
		return writeJSON(os.Stdout, advisory, false)
	}
	return renderAdvisory(os.Stdout, advisory)
}

// advisoryField is one label/value row of the rendered detail block.
type advisoryField struct {
	label string
	value string
}

// renderAdvisory writes a readable advisory detail block. It is nil-safe.
func renderAdvisory(w io.Writer, a *api.AdvisoryDetail) error {
	if a == nil {
		_, err := fmt.Fprintln(w, "no advisory data was returned")
		return err
	}

	fields := []advisoryField{
		{"GHSA id", firstNonEmpty(strings.TrimSpace(a.GHSAID), "-")},
		{"CVE id", firstNonEmpty(strings.TrimSpace(a.CVEID), "not assigned")},
		{"State", displayState(a.State)},
		{"Severity", displaySeverity(a.Severity)},
		{"CVSS score", a.CVSSScoreText()},
	}
	if vector := advisoryCVSSVector(a); vector != "" {
		fields = append(fields, advisoryField{"CVSS vector", vector})
	}
	fields = append(fields,
		advisoryField{"Summary", firstNonEmpty(strings.TrimSpace(a.Summary), "-")},
		advisoryField{"Affected", firstNonEmpty(a.AffectedSummary(), "-")},
		advisoryField{"CWE ids", firstNonEmpty(advisoryCWEText(a), "-")},
		advisoryField{"Credits", firstNonEmpty(advisoryCreditText(a), "-")},
		advisoryField{"Author", firstNonEmpty(advisoryAuthorLogin(a), "-")},
		advisoryField{"Created", firstNonEmpty(strings.TrimSpace(a.CreatedAt), "-")},
		advisoryField{"Updated", firstNonEmpty(strings.TrimSpace(a.UpdatedAt), "-")},
		advisoryField{"Published", firstNonEmpty(strings.TrimSpace(a.PublishedAt), "not published")},
		advisoryField{"URL", firstNonEmpty(strings.TrimSpace(a.HTMLURL), "-")},
	)

	for _, f := range fields {
		if _, err := fmt.Fprintf(w, "%-13s %s\n", f.label+":", f.value); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	return writeVerbatimBody(w, a.Description)
}

// renderComment writes one comment as a header line plus an indented body. It is
// nil-safe.
func renderComment(w io.Writer, c *api.Comment) error {
	if c == nil {
		_, err := fmt.Fprintln(w, "no comment data was returned")
		return err
	}

	header := "[" + firstNonEmpty(strings.TrimSpace(c.CreatedAt), "unknown time") + "] " + c.AuthorLogin()
	if association := strings.TrimSpace(c.AuthorAssociation); association != "" {
		header += " (" + association + ")"
	}
	if _, err := fmt.Fprintln(w, header+":"); err != nil {
		return err
	}

	body := strings.TrimRight(c.Body, "\n")
	if strings.TrimSpace(body) == "" {
		body = "(empty comment)"
	}
	for _, line := range strings.Split(body, "\n") {
		if _, err := fmt.Fprintf(w, "  %s\n", line); err != nil {
			return err
		}
	}
	return nil
}

// writeVerbatimBody writes a Markdown body unchanged, guaranteeing one trailing
// newline without stripping internal formatting.
func writeVerbatimBody(w io.Writer, body string) error {
	if strings.TrimSpace(body) == "" {
		_, err := fmt.Fprintln(w, "(no description provided)")
		return err
	}
	if _, err := io.WriteString(w, body); err != nil {
		return err
	}
	if !strings.HasSuffix(body, "\n") {
		_, err := fmt.Fprintln(w)
		return err
	}
	return nil
}

// advisoryCVSSVector returns the best available CVSS vector string.
func advisoryCVSSVector(a *api.AdvisoryDetail) string {
	if a == nil {
		return ""
	}
	if a.CVSS != nil {
		if v := strings.TrimSpace(a.CVSS.VectorString); v != "" {
			return v
		}
	}
	if a.CVSSSeverities != nil {
		if a.CVSSSeverities.CVSSV4 != nil {
			if v := strings.TrimSpace(a.CVSSSeverities.CVSSV4.VectorString); v != "" {
				return v
			}
		}
		if a.CVSSSeverities.CVSSV3 != nil {
			if v := strings.TrimSpace(a.CVSSSeverities.CVSSV3.VectorString); v != "" {
				return v
			}
		}
	}
	return ""
}

// advisoryCWEText joins the advisory's CWE ids, falling back to the expanded
// cwes list when cwe_ids is absent.
func advisoryCWEText(a *api.AdvisoryDetail) string {
	if a == nil {
		return ""
	}
	ids := make([]string, 0, len(a.CWEIDs))
	for _, id := range a.CWEIDs {
		if trimmed := strings.TrimSpace(id); trimmed != "" {
			ids = append(ids, trimmed)
		}
	}
	if len(ids) == 0 {
		for _, cwe := range a.CWEs {
			if trimmed := strings.TrimSpace(cwe.CWEID); trimmed != "" {
				ids = append(ids, trimmed)
			}
		}
	}
	return strings.Join(ids, ", ")
}

// advisoryCreditText joins the credited logins, preferring the simple credits
// list and falling back to the expanded one.
func advisoryCreditText(a *api.AdvisoryDetail) string {
	if a == nil {
		return ""
	}
	logins := make([]string, 0, len(a.Credits))
	for _, credit := range a.Credits {
		if login := strings.TrimSpace(credit.Login); login != "" {
			logins = append(logins, login)
		}
	}
	if len(logins) == 0 {
		for _, credit := range a.CreditsDetailed {
			if credit.User != nil {
				if login := strings.TrimSpace(credit.User.Login); login != "" {
					logins = append(logins, login)
				}
			}
		}
	}
	return strings.Join(logins, ", ")
}

// advisoryAuthorLogin returns the advisory author's login, or "" when unknown.
func advisoryAuthorLogin(a *api.AdvisoryDetail) string {
	if a == nil || a.Author == nil {
		return ""
	}
	return strings.TrimSpace(a.Author.Login)
}

// runCommentsCmd implements `ghsec comments <list|add|update>`.
func runCommentsCmd(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usagef("comments: a subcommand is required (list, add, update)\n\n%s", commentsUsage)
	}

	sub, rest := args[0], args[1:]
	switch sub {
	case "list", "ls":
		return runCommentsListCmd(ctx, rest)
	case "add", "create", "reply":
		return runCommentsAddCmd(ctx, rest)
	case "update", "edit":
		return runCommentsUpdateCmd(ctx, rest)
	case "-h", "--help", "help":
		fmt.Print(commentsUsage)
		return errFlagHandled
	default:
		return usagef("comments: unknown subcommand %q (use list, add or update)\n\n%s", sub, commentsUsage)
	}
}

// commentsListFlags are the inputs for `ghsec comments list`.
type commentsListFlags struct {
	advisoryTarget

	limit int
}

// register adds the comments list flags.
func (f *commentsListFlags) register(fs *flag.FlagSet) {
	f.advisoryTarget.register(fs)
	fs.IntVar(&f.limit, "limit", defaultCommentLimit, "maximum number of comments to print (1-100)")
}

// runCommentsListCmd implements `ghsec comments list`.
func runCommentsListCmd(ctx context.Context, args []string) error {
	var f commentsListFlags
	fs := buildFlagSet("comments list")
	f.register(fs)
	fs.Usage = func() { fmt.Fprint(os.Stderr, commentsUsage) }
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	target, err := f.target()
	if err != nil {
		return err
	}
	if f.limit < 1 || f.limit > maxPageSize {
		return usagef("--limit must be between 1 and %d (got %d)", maxPageSize, f.limit)
	}

	client, err := f.client()
	if err != nil {
		return err
	}

	items, err := collectPages(func(page, perPage int) (api.ListPage[api.Comment], error) {
		return client.ListComments(ctx, target.owner, target.repo, target.ghsa,
			api.AdvisoryListOptions{PerPage: perPage, Page: page})
	}, 1, f.limit)
	if err != nil {
		return fmt.Errorf("%s: %w", api.FriendlyMessage(err, "list the comments"), err)
	}

	if f.asJSON {
		return writeJSON(os.Stdout, items, false)
	}
	if len(items) == 0 {
		fmt.Fprintln(os.Stdout, "no comments found")
		return nil
	}
	for i := range items {
		if err := renderComment(os.Stdout, &items[i]); err != nil {
			return err
		}
	}
	return nil
}

// commentsAddFlags are the inputs for `ghsec comments add`.
type commentsAddFlags struct {
	advisoryTarget

	body     string
	bodyFile string
}

// register adds the comment creation flags.
func (f *commentsAddFlags) register(fs *flag.FlagSet) {
	f.advisoryTarget.register(fs)
	fs.StringVar(&f.body, "body", "", "comment text")
	fs.StringVar(&f.bodyFile, "body-file", "", "read the comment body from a file, or - for stdin")
}

// runCommentsAddCmd implements `ghsec comments add`.
func runCommentsAddCmd(ctx context.Context, args []string) error {
	var f commentsAddFlags
	fs := buildFlagSet("comments add")
	f.register(fs)
	fs.Usage = func() { fmt.Fprint(os.Stderr, commentsUsage) }
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	target, err := f.target()
	if err != nil {
		return err
	}

	body, err := resolveCommentBody(f.body, f.bodyFile)
	if err != nil {
		return err
	}

	client, err := f.client()
	if err != nil {
		return err
	}

	comment, err := client.CreateComment(ctx, target.owner, target.repo, target.ghsa, body)
	if err != nil {
		return fmt.Errorf("%s: %w", api.FriendlyMessage(err, "create the comment"), err)
	}

	if f.asJSON {
		return writeJSON(os.Stdout, comment, false)
	}
	if comment == nil {
		fmt.Fprintln(os.Stdout, "comment created")
		return nil
	}
	fmt.Fprintf(os.Stdout, "created comment %d\n", comment.ID)
	if url := strings.TrimSpace(comment.HTMLURL); url != "" {
		fmt.Fprintf(os.Stdout, "  url: %s\n", url)
	}
	return nil
}

// commentsUpdateFlags are the inputs for `ghsec comments update`.
type commentsUpdateFlags struct {
	advisoryTarget

	commentID int64
	body      string
	bodyFile  string
}

// register adds the comment update flags.
func (f *commentsUpdateFlags) register(fs *flag.FlagSet) {
	f.advisoryTarget.register(fs)
	fs.Int64Var(&f.commentID, "comment-id", 0, "numeric id of the comment to update (required)")
	fs.StringVar(&f.body, "body", "", "new comment text")
	fs.StringVar(&f.bodyFile, "body-file", "", "read the new comment body from a file, or - for stdin")
}

// runCommentsUpdateCmd implements `ghsec comments update`.
func runCommentsUpdateCmd(ctx context.Context, args []string) error {
	var f commentsUpdateFlags
	fs := buildFlagSet("comments update")
	f.register(fs)
	fs.Usage = func() { fmt.Fprint(os.Stderr, commentsUsage) }
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	target, err := f.target()
	if err != nil {
		return err
	}
	if f.commentID <= 0 {
		return usagef("--comment-id is required: pass the numeric id of the comment to update")
	}

	body, err := resolveCommentBody(f.body, f.bodyFile)
	if err != nil {
		return err
	}

	client, err := f.client()
	if err != nil {
		return err
	}

	comment, err := client.UpdateComment(ctx, target.owner, target.repo, target.ghsa, f.commentID, body)
	if err != nil {
		return fmt.Errorf("%s: %w", api.FriendlyMessage(err, "update the comment"), err)
	}

	if f.asJSON {
		return writeJSON(os.Stdout, comment, false)
	}
	fmt.Fprintf(os.Stdout, "updated comment %d\n", f.commentID)
	if comment != nil {
		if url := strings.TrimSpace(comment.HTMLURL); url != "" {
			fmt.Fprintf(os.Stdout, "  url: %s\n", url)
		}
	}
	return nil
}

// resolveCommentBody mirrors writeFlags.readDescription for comment bodies:
// inline text and a file are mutually exclusive, "-" means stdin, and the result
// must not be blank.
func resolveCommentBody(inline, file string) (string, error) {
	inline = strings.TrimSpace(inline)
	file = strings.TrimSpace(file)

	switch {
	case inline != "" && file != "":
		return "", usagef("use either --body or --body-file, not both")
	case file == "-":
		raw, err := io.ReadAll(io.LimitReader(os.Stdin, 8<<20))
		if err != nil {
			return "", fmt.Errorf("read the comment body from stdin: %w", err)
		}
		body := strings.TrimSpace(string(raw))
		if body == "" {
			return "", usagef("stdin was empty: pipe the comment body in, or use --body")
		}
		return body, nil
	case file != "":
		content, err := editor.ReadFile(file)
		if err != nil {
			return "", err
		}
		body := strings.TrimSpace(content)
		if body == "" {
			return "", usagef("the file %q is empty: nothing to post", file)
		}
		return body, nil
	case inline != "":
		return inline, nil
	default:
		return "", usagef("a comment body is required: pass --body TEXT or --body-file PATH (use - for stdin)")
	}
}

// cveRequestResult is the stable --json shape of `ghsec cve`.
type cveRequestResult struct {
	OK        bool   `json:"ok"`
	GHSAID    string `json:"ghsa_id"`
	Requested bool   `json:"requested"`
}

// runCVECmd implements `ghsec cve`.
func runCVECmd(ctx context.Context, args []string) error {
	var t advisoryTarget
	fs := buildFlagSet("cve")
	t.register(fs)
	fs.Usage = func() { fmt.Fprint(os.Stderr, cveUsage) }
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	target, err := t.target()
	if err != nil {
		return err
	}

	client, err := t.client()
	if err != nil {
		return err
	}

	if err := client.RequestCVE(ctx, target.owner, target.repo, target.ghsa); err != nil {
		return fmt.Errorf("%s: %w", api.FriendlyMessage(err, "request a CVE id"), err)
	}

	if t.asJSON {
		return writeJSON(os.Stdout, cveRequestResult{OK: true, GHSAID: target.ghsa, Requested: true}, true)
	}

	fmt.Fprintf(os.Stdout, "requested CVE for %s\n", target.ghsa)
	fmt.Fprintln(os.Stdout, "  GitHub assigns the CVE id asynchronously; re-run `ghsec show` to check.")
	return nil
}

// editFlags are the inputs for `ghsec edit`.
type editFlags struct {
	advisoryTarget

	summary     string
	description string
	descFile    string
	severity    string
	cve         string
	state       string
	cvssVector  string
	cweIDs      string
	dryRun      bool
}

// register adds the edit flags.
func (f *editFlags) register(fs *flag.FlagSet) {
	f.advisoryTarget.register(fs)
	fs.StringVar(&f.summary, "summary", "", "replace the one-line summary")
	fs.StringVar(&f.description, "description", "", "replace the description inline")
	fs.StringVar(&f.descFile, "description-file", "", "read the new description from a file, or - for stdin")
	fs.StringVar(&f.severity, "severity", "", "new severity: critical, high, medium or low")
	fs.StringVar(&f.cve, "cve", "", `set or replace the CVE id; pass "" to clear it`)
	fs.StringVar(&f.state, "state", "", "new state: draft, published or closed (triage is not settable)")
	fs.StringVar(&f.cvssVector, "cvss-vector", "", `set the CVSS vector; pass "" to clear it`)
	fs.StringVar(&f.cweIDs, "cwe-ids", "", `comma-separated CWE ids such as "CWE-79,CWE-89"; pass "" to clear`)
	fs.BoolVar(&f.dryRun, "dry-run", false, "print the JSON patch without calling GitHub")
}

// editMutationFlags lists the flags that change an advisory. At least one of
// them must be supplied to `ghsec edit`.
var editMutationFlags = []string{
	"summary", "description", "description-file", "severity",
	"cve", "state", "cvss-vector", "cwe-ids",
}

// buildPatch turns the flags the user actually passed into an update patch.
//
// Detection uses fs.Visit so that an explicit empty value (--cve "") is
// distinguishable from an omitted flag: only visited flags become pointers,
// which is what lets an empty string clear a field instead of being ignored.
func (f *editFlags) buildPatch(fs *flag.FlagSet) (api.AdvisoryUpdatePatch, error) {
	var patch api.AdvisoryUpdatePatch
	set := make(map[string]bool, len(editMutationFlags))
	fs.Visit(func(fl *flag.Flag) { set[fl.Name] = true })

	if set["description"] && set["description-file"] {
		return patch, usagef("use either --description or --description-file, not both")
	}

	if set["summary"] {
		summary := strings.TrimSpace(f.summary)
		if summary == "" {
			return patch, usagef("--summary must not be empty: omit the flag to keep the current summary")
		}
		if len([]rune(summary)) > maxSummaryLen {
			return patch, usagef("--summary must be at most %d characters (got %d)", maxSummaryLen, len([]rune(summary)))
		}
		patch.Summary = &summary
	}

	if set["description"] || set["description-file"] {
		description, err := resolveEditDescription(f.description, f.descFile)
		if err != nil {
			return patch, err
		}
		patch.Description = &description
	}

	if set["severity"] {
		severity, err := api.ParseSeverity(f.severity)
		if err != nil {
			return patch, usagef("%v", err)
		}
		patch.Severity = &severity
	}

	if set["cve"] {
		cve := strings.ToUpper(strings.TrimSpace(f.cve))
		if err := validateCVE(cve); err != nil {
			return patch, err
		}
		// An empty value is intentional here: it clears the CVE id.
		patch.CVEID = &cve
	}

	if set["state"] {
		state, err := api.ParseAdvisoryState(f.state)
		if err != nil {
			return patch, usagef("%v", err)
		}
		if !state.Editable() {
			return patch, usagef(
				"--state triage cannot be set: GitHub only allows moving an advisory to draft, published or closed")
		}
		patch.State = &state
	}

	if set["cvss-vector"] {
		vector := strings.TrimSpace(f.cvssVector)
		patch.CVSSVectorString = &vector
	}

	if set["cwe-ids"] {
		ids, err := parseCWEIDs(f.cweIDs)
		if err != nil {
			return patch, err
		}
		patch.CWEIDs = &ids
	}

	mutated := false
	for _, name := range editMutationFlags {
		if set[name] {
			mutated = true
			break
		}
	}
	if !mutated || patch.IsEmpty() {
		return patch, usagef("nothing to change: pass at least one of %s\n\n%s",
			strings.Join(editMutationFlags, ", "), editUsage)
	}

	return patch, nil
}

// resolveEditDescription resolves the replacement description, rejecting an
// empty body because GitHub's advisory description is mandatory.
func resolveEditDescription(inline, file string) (string, error) {
	file = strings.TrimSpace(file)
	if file == "" {
		description := strings.TrimSpace(inline)
		if description == "" {
			return "", usagef("--description must not be empty: omit the flag to keep the current description")
		}
		return description, nil
	}

	if file == "-" {
		raw, err := io.ReadAll(io.LimitReader(os.Stdin, 8<<20))
		if err != nil {
			return "", fmt.Errorf("read the description from stdin: %w", err)
		}
		description := strings.TrimSpace(string(raw))
		if description == "" {
			return "", usagef("stdin was empty: pipe the description in, or use --description")
		}
		return description, nil
	}

	content, err := editor.ReadFile(file)
	if err != nil {
		return "", err
	}
	description := strings.TrimSpace(content)
	if description == "" {
		return "", usagef("the file %q is empty: nothing to set", file)
	}
	return description, nil
}

// parseCWEIDs parses a comma-separated CWE list. An empty value is valid and
// yields an empty list, which clears the advisory's CWE ids.
func parseCWEIDs(raw string) ([]string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return []string{}, nil
	}

	ids := make([]string, 0, strings.Count(trimmed, ",")+1)
	seen := make(map[string]bool, len(ids))
	for _, part := range strings.Split(trimmed, ",") {
		id := strings.ToUpper(strings.TrimSpace(part))
		if id == "" {
			continue
		}
		if !cwePattern.MatchString(id) {
			return nil, usagef("--cwe-ids entries must look like CWE-79, got %q", part)
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, usagef("--cwe-ids contained no CWE ids: pass a comma-separated list such as CWE-79,CWE-89")
	}
	return ids, nil
}

// advisoryPatchPreview renders the patch in GitHub's wire shape for --dry-run.
//
// api.AdvisoryUpdatePatch hides Severity and State behind json:"-", so marshalling
// it directly would silently drop those fields from the preview.
func advisoryPatchPreview(p api.AdvisoryUpdatePatch) map[string]any {
	out := make(map[string]any)
	if p.Summary != nil {
		out["summary"] = *p.Summary
	}
	if p.Description != nil {
		out["description"] = *p.Description
	}
	if p.CVEID != nil {
		out["cve_id"] = *p.CVEID
	}
	if p.Severity != nil {
		out["severity"] = string(*p.Severity)
	}
	if p.CWEIDs != nil {
		out["cwe_ids"] = *p.CWEIDs
	}
	if p.State != nil {
		out["state"] = string(*p.State)
	}
	if len(p.Vulnerabilities) > 0 {
		out["vulnerabilities"] = p.Vulnerabilities
	}
	if p.CVSSVectorString != nil {
		out["cvss_vector_string"] = *p.CVSSVectorString
	}
	if len(p.CollaboratingUsers) > 0 {
		out["collaborating_users"] = p.CollaboratingUsers
	}
	if len(p.CollaboratingTeams) > 0 {
		out["collaborating_teams"] = p.CollaboratingTeams
	}
	return out
}

// runEditCmd implements `ghsec edit`.
func runEditCmd(ctx context.Context, args []string) error {
	var f editFlags
	fs := buildFlagSet("edit")
	f.register(fs)
	fs.Usage = func() { fmt.Fprint(os.Stderr, editUsage) }
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	target, err := f.target()
	if err != nil {
		return err
	}

	patch, err := f.buildPatch(fs)
	if err != nil {
		return err
	}

	if f.dryRun {
		// Dry run must work without credentials and must never touch the network.
		fmt.Fprintln(os.Stderr, "dry run: nothing was sent")
		return writeJSON(os.Stdout, advisoryPatchPreview(patch), false)
	}

	client, err := f.client()
	if err != nil {
		return err
	}

	updated, err := client.UpdateAdvisory(ctx, target.owner, target.repo, target.ghsa, patch)
	if err != nil {
		return fmt.Errorf("%s: %w", api.FriendlyMessage(err, "update the advisory"), err)
	}

	if f.asJSON {
		return writeJSON(os.Stdout, updated, false)
	}

	if updated == nil {
		fmt.Fprintf(os.Stdout, "updated %s\n", target.ghsa)
		return nil
	}

	id := firstNonEmpty(strings.TrimSpace(updated.GHSAID), target.ghsa)
	fmt.Fprintf(os.Stdout, "updated %s\n", id)
	fmt.Fprintf(os.Stdout, "  state:    %s\n", displayState(updated.State))
	fmt.Fprintf(os.Stdout, "  severity: %s\n", displaySeverity(updated.Severity))
	if url := strings.TrimSpace(updated.HTMLURL); url != "" {
		fmt.Fprintf(os.Stdout, "  url:      %s\n", url)
	}
	return nil
}
