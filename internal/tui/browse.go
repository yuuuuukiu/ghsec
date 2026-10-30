package tui

// The advisory browser: a list of the repository's advisories, a detail screen
// with the reply thread, and the maintainer actions (reply, request a CVE, edit).
//
// Only the interactive wrappers touch a terminal, and they always go through
// runForm so the degenerate-terminal guard in safeform.go applies. The fetch and
// render helpers are deliberately free of any terminal access: the CLI reuses
// them and the tests exercise them without a TTY.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/charmbracelet/huh"

	"github.com/yuuuuukiu/ghsec/internal/api"
)

const (
	// browsePageSize is GitHub's maximum page size for advisory listings.
	browsePageSize = 100

	// browseListLimit caps how many advisories one browser session loads.
	browseListLimit = 200

	// browseCommentLimit caps how many replies are fetched for one advisory.
	browseCommentLimit = 300

	// browseMaxPages is a hard stop for pagination loops, so a server that keeps
	// advertising a next page can never spin forever.
	browseMaxPages = 50

	// browseMinWidth and browseMaxWidth clamp the panel layout width.
	browseMinWidth = 40
	browseMaxWidth = 120

	// browseMaxCommentLines is how much of a single reply is shown before it is
	// truncated: advisory threads can contain very long Markdown.
	browseMaxCommentLines = 18

	// browseMaxCommentRunes bounds how much Markdown is handed to glamour.
	browseMaxCommentRunes = 4000
)

// FetchAdvisories pages through a repository's advisories until limit items have
// been collected or GitHub reports no further page.
//
// state may be empty to list every state. The returned slice is never nil on
// success, so callers can always range over it.
func FetchAdvisories(ctx context.Context, client *api.Client, owner, repo string, state api.AdvisoryState, limit int) ([]api.AdvisoryDetail, error) {
	if client == nil {
		return nil, errors.New("no GitHub client configured")
	}
	if limit <= 0 {
		limit = browseListLimit
	}

	advisories := make([]api.AdvisoryDetail, 0, browseInitialCap(limit))
	for page := 1; len(advisories) < limit && page > 0; {
		if err := browseCtxErr(ctx); err != nil {
			return nil, err
		}

		perPage := limit - len(advisories)
		if perPage > browsePageSize {
			perPage = browsePageSize
		}

		result, err := client.ListAdvisories(ctx, owner, repo, api.AdvisoryListOptions{
			State:   state,
			PerPage: perPage,
			Page:    page,
		})
		if err != nil {
			return nil, err
		}

		items := result.Items
		if len(items) == 0 {
			break
		}
		// GitHub may return a full page even when only a few more items were
		// asked for; never overshoot the caller's limit.
		if room := limit - len(advisories); len(items) > room {
			items = items[:room]
		}
		advisories = append(advisories, items...)

		page = browseNextPage(page, result)
	}
	return advisories, nil
}

// FetchComments pages through the reply thread of one advisory. The thread is
// capped at browseCommentLimit replies.
func FetchComments(ctx context.Context, client *api.Client, owner, repo, ghsaID string) ([]api.Comment, error) {
	if client == nil {
		return nil, errors.New("no GitHub client configured")
	}
	ghsaID = strings.TrimSpace(ghsaID)
	if ghsaID == "" {
		return nil, errors.New("no advisory id supplied")
	}

	limit := browseCommentLimit
	comments := make([]api.Comment, 0, 16)
	for page := 1; len(comments) < limit && page > 0; {
		if err := browseCtxErr(ctx); err != nil {
			return nil, err
		}

		perPage := limit - len(comments)
		if perPage > browsePageSize {
			perPage = browsePageSize
		}

		result, err := client.ListComments(ctx, owner, repo, ghsaID, api.AdvisoryListOptions{
			PerPage: perPage,
			Page:    page,
		})
		if err != nil {
			return nil, err
		}

		items := result.Items
		if len(items) == 0 {
			break
		}
		if room := limit - len(comments); len(items) > room {
			items = items[:room]
		}
		comments = append(comments, items...)

		page = browseNextPage(page, result)
	}
	return comments, nil
}

// browseNextPage derives the next page number from a list page. It returns 0
// when the listing is exhausted (or when the server's answer would loop).
func browseNextPage[T any](current int, result api.ListPage[T]) int {
	next := result.NextPage
	if next <= 0 {
		if !result.HasMore {
			return 0
		}
		next = current + 1
	}
	if next <= current || next > browseMaxPages {
		return 0
	}
	return next
}

// browseCtxErr surfaces context cancellation to the pure data path.
func browseCtxErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

// browseInitialCap keeps the slice hint small for large limits.
func browseInitialCap(limit int) int {
	switch {
	case limit < 0:
		return 0
	case limit > 50:
		return 50
	default:
		return limit
	}
}

// BrowseAdvisories is the interactive advisory browser for one repository. It
// loops until the user backs out; ctx cancellation aborts cleanly. It returns
// ErrAborted only when the user cancels the whole flow (ctrl+c).
func BrowseAdvisories(ctx context.Context, client *api.Client, owner, repo string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if client == nil {
		fmt.Println(ErrorPanel("Not signed in", "Configure an API key from the profiles menu first."))
		return nil
	}

	repoName := browseRepoLabel(owner, repo)

	state, err := promptBrowseFilter("")
	if err != nil {
		return err
	}

	width := browseWidth()
	for {
		if ctx.Err() != nil {
			return ErrAborted
		}

		advisories, err := FetchAdvisories(ctx, client, owner, repo, state, browseListLimit)
		if err != nil {
			if ctx.Err() != nil {
				return ErrAborted
			}
			// A transient API failure must not tear the whole application down.
			fmt.Println()
			fmt.Println(ErrorPanel("Could not load advisories",
				api.FriendlyMessage(err, "load the advisories of "+repoName)))
			return nil
		}

		if len(advisories) == 0 {
			fmt.Println()
			fmt.Println(InfoPanel("No advisories found for "+repoName, browseEmptyListBody(state)))
			return nil
		}

		choice, err := promptBrowseList(repoName, state, advisories, width)
		if err != nil {
			return err
		}

		switch choice.kind {
		case browseChoiceAdvisory:
			if choice.index < 0 || choice.index >= len(advisories) {
				continue
			}
			selected := &advisories[choice.index]
			id := strings.TrimSpace(selected.GHSAID)
			if id == "" {
				id = strings.TrimSpace(selected.CVEID)
			}
			if id == "" {
				fmt.Println()
				fmt.Println(WarnPanel("Cannot open this advisory",
					"GitHub returned no GHSA id for it, so it cannot be addressed individually."))
				continue
			}
			if err := ViewAdvisory(ctx, client, owner, repo, id); err != nil {
				return err
			}
		case browseChoiceFilter:
			next, err := promptBrowseFilter(state)
			if err != nil {
				return err
			}
			state = next
		case browseChoiceRefresh:
			// The next iteration re-fetches the list.
		case browseChoiceBack:
			return nil
		}
	}
}

// browseEmptyListBody explains an empty listing, naming the active filter.
func browseEmptyListBody(state api.AdvisoryState) string {
	lines := []string{Muted("Nothing matched the current state filter (" + browseFilterLabel(state) + ").")}
	lines = append(lines, Muted("If you expected an advisory here, check that the repository has security advisories enabled."))
	return strings.Join(lines, "\n")
}

// ViewAdvisory renders one advisory (detail plus replies) and offers the
// maintainer actions. It returns nil when the user goes back and ErrAborted on
// ctrl+c.
func ViewAdvisory(ctx context.Context, client *api.Client, owner, repo, ghsaID string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ghsaID = strings.TrimSpace(ghsaID)
	if client == nil {
		fmt.Println(ErrorPanel("Not signed in", "Configure an API key from the profiles menu first."))
		return nil
	}
	if ghsaID == "" {
		fmt.Println(ErrorPanel("Cannot open this advisory", "No GHSA identifier was supplied."))
		return nil
	}

	width := browseWidth()
	for {
		if ctx.Err() != nil {
			return ErrAborted
		}

		advisory, err := client.GetAdvisory(ctx, owner, repo, ghsaID)
		if err != nil {
			if ctx.Err() != nil {
				return ErrAborted
			}
			fmt.Println()
			fmt.Println(ErrorPanel("Could not load "+ghsaID,
				api.FriendlyMessage(err, "load the advisory "+ghsaID)))
			retry, ferr := promptRetryBack()
			if ferr != nil {
				return ferr
			}
			if !retry {
				return nil
			}
			continue
		}

		// The detail is the important part; a failing thread request is shown
		// but does not stop the user from acting on the advisory.
		comments, cerr := FetchComments(ctx, client, owner, repo, ghsaID)
		if cerr != nil {
			if ctx.Err() != nil {
				return ErrAborted
			}
			fmt.Println()
			fmt.Println(ErrorPanel("Could not load the replies",
				api.FriendlyMessage(cerr, "load the replies of "+ghsaID)))
			comments = nil
		}

		fmt.Println()
		fmt.Println(RenderAdvisoryDetail(advisory, width))
		fmt.Println()
		fmt.Println(RenderCommentThread(comments, width))
		fmt.Println()

		action, err := promptAdvisoryActions(advisory, owner, repo, ghsaID)
		if err != nil {
			return err
		}

		switch action {
		case viewActionComment:
			if err := addAdvisoryComment(ctx, client, owner, repo, ghsaID); err != nil {
				return err
			}
		case viewActionCVE:
			if err := requestAdvisoryCVE(ctx, client, owner, repo, ghsaID, advisory); err != nil {
				return err
			}
		case viewActionEdit:
			if err := editAdvisory(ctx, client, owner, repo, ghsaID, advisory); err != nil {
				return err
			}
		case viewActionRefresh:
			// The next iteration re-fetches the detail and the thread.
		case viewActionBack:
			return nil
		}
	}
}

// RenderAdvisoryDetail renders an advisory as a styled panel. It is nil-safe and
// normalises a non-positive width to 80 columns.
func RenderAdvisoryDetail(a *api.AdvisoryDetail, width int) string {
	if a == nil {
		return InfoPanel("No advisory details",
			Muted("GitHub returned no advisory, so there is nothing to show."))
	}

	w := mdWidth(width)
	inner := w - 4
	if inner < 20 {
		inner = 20
	}

	rows := make([]string, 0, 18)
	if summary := browseOneLine(a.Summary); summary != "" {
		rows = append(rows, Header(summary), "")
	}

	rows = append(rows, KeyValue("State", StateBadge(a.AdvisoryStateValue())))
	if sev, err := api.ParseSeverity(a.Severity); err == nil {
		rows = append(rows, KeyValue("Severity", SeverityBadge(sev)))
	} else {
		rows = append(rows, KeyValue("Severity", Muted("not set")))
	}
	rows = append(rows, KeyValue("CVSS", a.CVSSScoreText()))
	if cve := browseSanitiseText(strings.TrimSpace(a.CVEID)); cve != "" {
		rows = append(rows, KeyValue("CVE", Accent(cve)))
	} else {
		rows = append(rows, KeyValue("CVE", Muted("not assigned")))
	}
	rows = append(rows, KeyValue("Author", browseSanitiseText(a.AuthorLogin())))
	for _, stamp := range []struct{ label, value string }{
		{"Created", a.CreatedAt},
		{"Updated", a.UpdatedAt},
		{"Published", a.PublishedAt},
	} {
		if value := browseSanitiseText(strings.TrimSpace(stamp.value)); value != "" {
			rows = append(rows, KeyValue(stamp.label, value))
		}
	}
	if affected := browseSanitiseText(a.AffectedSummary()); affected != "" {
		rows = append(rows, KeyValue("Affected", affected))
	}
	if cwes := browseSanitiseText(strings.Join(a.CWEIDs, ", ")); cwes != "" {
		rows = append(rows, KeyValue("CWE", cwes))
	}
	if credits := browseCreditLogins(a); credits != "" {
		rows = append(rows, KeyValue("Credits", credits))
	}
	if collaborators := browseUserLogins(a.CollaboratingUsers); collaborators != "" {
		rows = append(rows, KeyValue("Collaborators", collaborators))
	}
	if link := browseSanitiseText(strings.TrimSpace(a.HTMLURL)); link != "" {
		rows = append(rows, KeyValue("URL", Accent(link)))
	}

	body := strings.Join(rows, "\n") + "\n" + divider(inner) + "\n"
	if description := strings.TrimSpace(a.Description); description != "" {
		// Sanitise the source: the description is remote text, so its control
		// characters must not reach the terminal even if glamour passes them on.
		description = browseSanitiseMultiline(description)
		rendered := RenderMarkdown(description, inner)
		if strings.TrimSpace(rendered) == "" {
			rendered = description
		}
		body += rendered
	} else {
		body += Muted("(no description)")
	}

	return Box(browseSanitiseText(a.Identifier()), body, colPrimary)
}

// RenderCommentThread renders the advisory replies as a readable thread. An
// empty (or nil) slice still renders a friendly placeholder.
func RenderCommentThread(comments []api.Comment, width int) string {
	w := mdWidth(width)
	inner := w - 4
	if inner < 20 {
		inner = 20
	}

	if len(comments) == 0 {
		return Muted("no comments yet")
	}

	blocks := make([]string, 0, len(comments)+1)
	blocks = append(blocks, Header(fmt.Sprintf("Replies (%d)", len(comments))))
	for i := range comments {
		comment := &comments[i]
		blocks = append(blocks, Box(browseCommentTitle(comment), browseCommentBody(comment, inner), colAccent))
	}
	return strings.Join(blocks, "\n")
}

// browseCommentTitle builds the per-reply header line.
func browseCommentTitle(c *api.Comment) string {
	parts := make([]string, 0, 3)
	if login := browseSanitiseText(strings.TrimSpace(c.AuthorLogin())); login != "" {
		parts = append(parts, "@"+login)
	}
	if assoc := browseSanitiseText(strings.TrimSpace(c.AuthorAssociation)); assoc != "" {
		parts = append(parts, strings.ToLower(assoc))
	}
	if stamp := browseSanitiseText(strings.TrimSpace(c.CreatedAt)); stamp != "" {
		parts = append(parts, stamp)
	}
	if len(parts) == 0 {
		return "(anonymous reply)"
	}
	return strings.Join(parts, "  ·  ")
}

// browseCommentBody renders one reply body, bounding both the Markdown handed to
// glamour and the number of lines shown.
func browseCommentBody(c *api.Comment, inner int) string {
	body := strings.TrimSpace(c.Body)
	if body == "" {
		return Muted("(empty reply)")
	}
	// The reply is remote text: strip control characters before rendering.
	body = browseSanitiseMultiline(body)
	if runes := []rune(body); len(runes) > browseMaxCommentRunes {
		body = string(runes[:browseMaxCommentRunes]) + "\n\n…"
	}

	rendered := RenderMarkdown(body, inner)
	if strings.TrimSpace(rendered) == "" {
		rendered = body
	}
	return browseCapLines(rendered, browseMaxCommentLines)
}

// browseCapLines truncates a rendered block to at most max lines.
func browseCapLines(s string, max int) string {
	if max <= 0 {
		return s
	}
	lines := strings.Split(s, "\n")
	if len(lines) <= max {
		return s
	}
	return strings.Join(lines[:max], "\n") + "\n" + Muted("… truncated")
}

// browseCreditLogins collects the credited logins, de-duplicated.
func browseCreditLogins(a *api.AdvisoryDetail) string {
	if a == nil {
		return ""
	}
	seen := make(map[string]bool, len(a.Credits)+len(a.CreditsDetailed))
	logins := make([]string, 0, len(a.Credits)+len(a.CreditsDetailed))
	add := func(login string) {
		login = browseSanitiseText(strings.TrimSpace(login))
		if login == "" || seen[login] {
			return
		}
		seen[login] = true
		logins = append(logins, login)
	}
	for _, credit := range a.Credits {
		add(credit.Login)
	}
	for _, credit := range a.CreditsDetailed {
		if credit.User != nil {
			add(credit.User.Login)
		}
	}
	return strings.Join(logins, ", ")
}

// browseUserLogins lists the logins of a user slice, skipping empty entries.
func browseUserLogins(users []api.SimpleUser) string {
	logins := make([]string, 0, len(users))
	for _, user := range users {
		if login := browseSanitiseText(strings.TrimSpace(user.Login)); login != "" {
			logins = append(logins, login)
		}
	}
	return strings.Join(logins, ", ")
}

// browseRepoLabel renders owner/repo, tolerating a missing half.
func browseRepoLabel(owner, repo string) string {
	owner = strings.TrimSpace(owner)
	repo = strings.TrimSpace(repo)
	switch {
	case owner == "" && repo == "":
		return "(unknown repository)"
	case owner == "":
		return repo
	case repo == "":
		return owner
	default:
		return owner + "/" + repo
	}
}

// browseFilterLabel names the active state filter.
func browseFilterLabel(state api.AdvisoryState) string {
	if !state.Valid() {
		return "all states"
	}
	return state.Label()
}

// browseOneLine collapses whitespace so multi-line text fits in one line. Raw
// text that is printed without going through RenderMarkdown also passes through
// browseSanitiseText, so a crafted summary cannot smuggle terminal escapes in.
func browseOneLine(s string) string {
	return browseSanitiseText(strings.Join(strings.Fields(s), " "))
}

// browseSanitiseText removes C0/C1 control characters and DEL from a single-line
// value. Advisory fields are authored by remote users, so they are displayed as
// data only: an escape sequence in a summary must never reach the terminal.
func browseSanitiseText(s string) string {
	if !strings.ContainsFunc(s, browseIsControlRune) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if browseIsControlRune(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// browseSanitiseMultiline removes control characters from a multi-line,
// Markdown-authored value while keeping the newlines and tabs that are part of
// the text. Stripping them from the *source* before rendering means glamour only
// ever emits its own styling sequences, so advisory text cannot inject terminal
// escapes into the browser.
func browseSanitiseMultiline(s string) string {
	if !strings.ContainsFunc(s, browseIsControlRune) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if browseIsControlRune(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// browseIsControlRune reports whether r is a control character that has no place
// in rendered output. Tabs and newlines are handled by the caller.
func browseIsControlRune(r rune) bool {
	switch {
	case r == '\t', r == '\n', r == '\r':
		return false
	case r < 0x20, r == 0x7f:
		return true
	case r >= 0x80 && r <= 0x9f:
		return true
	default:
		return false
	}
}

// browseTruncateRunes shortens s to at most max runes, adding an ellipsis.
func browseTruncateRunes(s string, max int) string {
	s = browseSanitiseText(strings.TrimSpace(s))
	if max <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	if max == 1 {
		return "…"
	}
	return string(runes[:max-1]) + "…"
}

// browseWidth returns the width panels should be laid out at, falling back to a
// classic 80 columns when the terminal does not report a size.
func browseWidth() int {
	if width, _, ok := terminalSize(); ok && width > 0 {
		if width < browseMinWidth {
			return browseMinWidth
		}
		if width > browseMaxWidth {
			return browseMaxWidth
		}
		return width
	}
	return defaultMDWidth
}

// browseChoiceKind distinguishes an advisory row from the list commands.
type browseChoiceKind int

const (
	browseChoiceAdvisory browseChoiceKind = iota
	browseChoiceRefresh
	browseChoiceFilter
	browseChoiceBack
)

// browseChoice is the value bound to the advisory list picker.
type browseChoice struct {
	kind  browseChoiceKind
	index int
}

// promptBrowseFilter asks which advisory states to list. An empty state means
// "all states".
func promptBrowseFilter(current api.AdvisoryState) (api.AdvisoryState, error) {
	choice := current
	if !choice.Valid() {
		choice = ""
	}

	options := make([]huh.Option[api.AdvisoryState], 0, len(api.AdvisoryStates)+1)
	options = append(options, huh.NewOption("All states", api.AdvisoryState("")))
	for _, state := range api.AdvisoryStates {
		options = append(options, huh.NewOption(state.Label(), state))
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[api.AdvisoryState]().
				Title("Which advisories?").
				Description("Filter the repository's advisories by lifecycle state.").
				Options(options...).
				Value(&choice),
		),
	).WithTheme(Theme()).WithShowHelp(true)

	if err := runForm(form); err != nil {
		return "", err
	}
	return choice, nil
}

// promptBrowseList shows one advisory per option plus the list commands.
func promptBrowseList(repoName string, state api.AdvisoryState, advisories []api.AdvisoryDetail, width int) (browseChoice, error) {
	choice := browseChoice{kind: browseChoiceAdvisory}

	options := make([]huh.Option[browseChoice], 0, len(advisories)+3)
	for i := range advisories {
		options = append(options, huh.NewOption(
			browseAdvisoryLabel(&advisories[i], width),
			browseChoice{kind: browseChoiceAdvisory, index: i},
		))
	}
	options = append(options,
		huh.NewOption("Refresh the list", browseChoice{kind: browseChoiceRefresh}),
		huh.NewOption("Change the state filter (now: "+browseFilterLabel(state)+")", browseChoice{kind: browseChoiceFilter}),
		huh.NewOption("Back to the main menu", browseChoice{kind: browseChoiceBack}),
	)

	count := fmt.Sprintf("%d advisories", len(advisories))
	if len(advisories) == 1 {
		count = "1 advisory"
	}
	description := strings.Join([]string{
		Accent(repoName),
		Muted(count + "  ·  filter: " + browseFilterLabel(state)),
		Muted("Up/down to move, enter to open, ctrl+c to cancel."),
	}, "\n")

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[browseChoice]().
				Title("Advisories in " + repoName).
				Description(description).
				Options(options...).
				Value(&choice),
		),
	).WithTheme(Theme()).WithShowHelp(true)

	if err := runForm(form); err != nil {
		return browseChoice{}, err
	}
	return choice, nil
}

// browseAdvisoryLabel renders one row of the advisory list, e.g.
// "[published] GHSA-xxxx-xxxx-xxxx  high  CVE-2024-1234  —  summary…".
//
// A non-positive width is normalised to 80 columns so the row is never empty.
func browseAdvisoryLabel(a *api.AdvisoryDetail, width int) string {
	if a == nil {
		return "(nameless advisory)"
	}
	width = mdWidth(width)

	state := a.AdvisoryStateValue()
	stateText := "unknown"
	if state.Valid() {
		stateText = string(state)
	}
	severity := "no severity"
	if sev, err := api.ParseSeverity(a.Severity); err == nil {
		severity = string(sev)
	}

	prefix := fmt.Sprintf("[%s] %s  %s", stateText,
		browseSanitiseText(a.Identifier()), severity)
	if cve := browseSanitiseText(strings.TrimSpace(a.CVEID)); cve != "" {
		prefix += "  " + cve
	}
	if utf8.RuneCountInString(prefix) > width {
		prefix = browseTruncateRunes(prefix, width)
	}

	summary := browseOneLine(a.Summary)
	if summary == "" {
		return prefix
	}
	budget := width - utf8.RuneCountInString(prefix) - 5
	if budget < 24 {
		budget = 24
	}
	if budget > 90 {
		budget = 90
	}
	return prefix + "  —  " + browseTruncateRunes(summary, budget)
}

// viewAction is one choice on the advisory detail screen.
type viewAction int

const (
	viewActionComment viewAction = iota
	viewActionCVE
	viewActionEdit
	viewActionRefresh
	viewActionBack
)

// promptAdvisoryActions shows the detail-screen actions.
func promptAdvisoryActions(a *api.AdvisoryDetail, owner, repo, ghsaID string) (viewAction, error) {
	action := viewActionComment

	description := []string{Muted(browseRepoLabel(owner, repo) + "  ·  " + ghsaID)}
	if a != nil {
		state := a.AdvisoryStateValue()
		stateText := "unknown state"
		if state.Valid() {
			stateText = state.Label()
		}
		line := stateText
		if sev, err := api.ParseSeverity(a.Severity); err == nil {
			line += "  ·  " + api.SeverityLabel(sev)
		}
		if cve := strings.TrimSpace(a.CVEID); cve != "" {
			line += "  ·  " + cve
		}
		description = append(description, Muted(line))
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[viewAction]().
				Title("What would you like to do?").
				Description(strings.Join(description, "\n")).
				Options(
					huh.NewOption("Add a comment / reply", viewActionComment),
					huh.NewOption("Request a CVE id", viewActionCVE),
					huh.NewOption("Edit this advisory", viewActionEdit),
					huh.NewOption("Refresh", viewActionRefresh),
					huh.NewOption("Back", viewActionBack),
				).
				Value(&action),
		),
	).WithTheme(Theme()).WithShowHelp(true)

	if err := runForm(form); err != nil {
		return viewActionBack, err
	}
	return action, nil
}

// promptRetryBack is the small menu shown after a failed load.
func promptRetryBack() (bool, error) {
	retry := true
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[bool]().
				Title("What would you like to do?").
				Description(Muted("The last request did not succeed.")).
				Options(
					huh.NewOption("Retry now", true),
					huh.NewOption("Back to the advisory list", false),
				).
				Value(&retry),
		),
	).WithTheme(Theme()).WithShowHelp(true)

	if err := runForm(form); err != nil {
		return false, err
	}
	return retry, nil
}

// addAdvisoryComment asks for a reply body and posts it.
func addAdvisoryComment(ctx context.Context, client *api.Client, owner, repo, ghsaID string) error {
	body, err := promptCommentBody(ghsaID)
	if err != nil {
		return err
	}
	if strings.TrimSpace(body) == "" {
		fmt.Println()
		fmt.Println(WarnPanel("Empty reply", "Nothing was sent because the reply body is empty."))
		return nil
	}

	comment, err := client.CreateComment(ctx, owner, repo, ghsaID, body)
	if err != nil {
		if ctx.Err() != nil {
			return ErrAborted
		}
		fmt.Println()
		fmt.Println(ErrorPanel("Could not post the reply", api.FriendlyMessage(err, "post the reply")))
		return nil
	}

	lines := make([]string, 0, 3)
	if comment != nil {
		if link := strings.TrimSpace(comment.HTMLURL); link != "" {
			lines = append(lines, KeyValue("Reply", Accent(link)))
		} else if link := strings.TrimSpace(comment.URL); link != "" {
			lines = append(lines, KeyValue("Reply", Accent(link)))
		}
	}
	if len(lines) == 0 {
		lines = append(lines, Muted("GitHub accepted the reply but returned no details."))
	}
	lines = append(lines, "", Muted("It is now part of the advisory's comment thread."))

	fmt.Println()
	fmt.Println(SuccessPanel("Reply posted", strings.Join(lines, "\n")))
	return nil
}

// promptCommentBody collects a multi-line Markdown reply.
func promptCommentBody(ghsaID string) (string, error) {
	var body string
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewText().
				Title("Reply to " + ghsaID).
				Description("Markdown is supported. Enter submits, alt+enter (or ctrl+j) starts a new line.").
				Lines(8).
				Value(&body),
		),
	).WithTheme(Theme()).WithShowHelp(true)

	if err := runForm(form); err != nil {
		return "", err
	}
	return strings.TrimSpace(body), nil
}

// requestAdvisoryCVE asks GitHub to issue a CVE id for the advisory.
func requestAdvisoryCVE(ctx context.Context, client *api.Client, owner, repo, ghsaID string, advisory *api.AdvisoryDetail) error {
	if advisory != nil && advisory.CVEStatus() == api.CVEAssigned {
		fmt.Println()
		fmt.Println(InfoPanel("A CVE id is already assigned",
			KeyValue("CVE", Accent(advisory.CVEID))+"\n"+
				Muted("No new request was sent; GitHub has already issued an id for this advisory.")))
		return nil
	}

	confirmed, err := RunConfirm(
		"Request a CVE id for "+ghsaID+"? GitHub queues the request and assigns the id asynchronously.",
		false)
	if err != nil {
		return err
	}
	if !confirmed {
		fmt.Println()
		fmt.Println(Muted("CVE request cancelled."))
		return nil
	}

	if err := client.RequestCVE(ctx, owner, repo, ghsaID); err != nil {
		if ctx.Err() != nil {
			return ErrAborted
		}
		fmt.Println()
		fmt.Println(ErrorPanel("Could not request a CVE id", api.FriendlyMessage(err, "request a CVE id")))
		return nil
	}

	fmt.Println()
	fmt.Println(SuccessPanel("CVE id requested", strings.Join([]string{
		KeyValue("Request", Accent("queued (HTTP 202)")),
		"",
		Muted("This is asynchronous: GitHub assigns the CVE id later, usually within a few days."),
		Muted("Refresh this advisory to see the id once it appears in the identifiers."),
	}, "\n")))
	return nil
}

// advisoryEditInput is the data gathered by the advisory editor.
type advisoryEditInput struct {
	Summary     string
	Description string
	Severity    api.Severity
	State       api.AdvisoryState
	CVEID       string
}

// advisoryEditBaseline records the values the edit form started with, so a patch
// only carries fields the user actually changed. This matters because PATCH
// treats an empty value as "clear this field", not as "leave it alone".
type advisoryEditBaseline struct {
	summary     string
	description string
	severity    api.Severity
	state       api.AdvisoryState
	cveID       string
}

// newAdvisoryEditInput pre-fills the editor from the fetched advisory.
func newAdvisoryEditInput(original *api.AdvisoryDetail) advisoryEditInput {
	in := advisoryEditInput{
		Severity: api.SeverityMedium,
		State:    firstEditableState(),
	}
	if original == nil {
		return in
	}

	in.Summary = strings.TrimSpace(original.Summary)
	in.Description = original.Description
	in.CVEID = strings.TrimSpace(original.CVEID)
	if sev, err := api.ParseSeverity(original.Severity); err == nil {
		in.Severity = sev
	}
	if state := original.AdvisoryStateValue(); state.Editable() {
		in.State = state
	}
	return in
}

// firstEditableState is the state offered when the current one cannot be set
// through the API (triage is assigned by GitHub).
func firstEditableState() api.AdvisoryState {
	for _, state := range api.AdvisoryStates {
		if state.Editable() {
			return state
		}
	}
	return api.StateDraft
}

// editableStateOptions lists the states PATCH accepts.
func editableStateOptions() []huh.Option[api.AdvisoryState] {
	options := make([]huh.Option[api.AdvisoryState], 0, len(api.AdvisoryStates))
	for _, state := range api.AdvisoryStates {
		if !state.Editable() {
			continue
		}
		options = append(options, huh.NewOption(state.Label(), state))
	}
	return options
}

// newAdvisoryEditForm builds the editor without running it.
func newAdvisoryEditForm(in *advisoryEditInput) *huh.Form {
	return huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Summary").
				Description("One line that describes the vulnerability (maximum 256 characters).").
				CharLimit(summaryMaxLen).
				Value(&in.Summary).
				Validate(validateSummary),
			huh.NewText().
				Title("Description").
				Description("Markdown is supported. Enter submits, alt+enter (or ctrl+j) starts a new line.").
				Lines(10).
				Value(&in.Description).
				Validate(validateDescription),
		).Title("Summary and description"),
		huh.NewGroup(
			huh.NewSelect[api.Severity]().
				Title("Severity").
				Options(severityOptions()...).
				Value(&in.Severity),
			huh.NewSelect[api.AdvisoryState]().
				Title("State").
				Description("Only draft, published and closed can be set through the API.").
				Options(editableStateOptions()...).
				Value(&in.State),
			huh.NewInput().
				Title("CVE ID").
				Description("Leave blank to clear the CVE id. Example: CVE-2024-1234").
				Placeholder("CVE-2024-1234").
				Value(&in.CVEID).
				Validate(cveValidator),
		).Title("Severity, state and CVE"),
	).WithTheme(Theme()).WithShowHelp(true)
}

// editAdvisory runs the editor and PATCHes only the changed fields.
func editAdvisory(ctx context.Context, client *api.Client, owner, repo, ghsaID string, original *api.AdvisoryDetail) error {
	if original == nil {
		fmt.Println()
		fmt.Println(WarnPanel("Nothing to edit",
			"The advisory could not be loaded, so the editor was not opened. Refresh first."))
		return nil
	}

	in := newAdvisoryEditInput(original)
	baseline := advisoryEditBaseline{
		summary:     strings.TrimSpace(original.Summary),
		description: strings.TrimSpace(original.Description),
		severity:    in.Severity,
		state:       in.State,
		cveID:       browseNormaliseCVEID(original.CVEID),
	}

	if err := runForm(newAdvisoryEditForm(&in)); err != nil {
		return err
	}

	patch, changes := buildAdvisoryUpdate(in, baseline)
	if len(changes) == 0 {
		fmt.Println()
		fmt.Println(InfoPanel("Nothing to change",
			Muted("The values you submitted match the current advisory, so no update was sent.")))
		return nil
	}

	updated, err := client.UpdateAdvisory(ctx, owner, repo, ghsaID, patch)
	if err != nil {
		if ctx.Err() != nil {
			return ErrAborted
		}
		fmt.Println()
		fmt.Println(ErrorPanel("Could not update "+ghsaID,
			api.FriendlyMessage(err, "update the advisory "+ghsaID)))
		return nil
	}

	body := KeyValue("Changed", strings.Join(changes, ", "))
	if updated != nil {
		if link := strings.TrimSpace(updated.HTMLURL); link != "" {
			body += "\n" + KeyValue("Open", Accent(link))
		}
	}
	fmt.Println()
	fmt.Println(SuccessPanel("Advisory updated", body))
	return nil
}

// browseNormaliseCVEID upper-cases a CVE id, tolerating an invalid leftover.
func browseNormaliseCVEID(raw string) string {
	if normalised, err := validateCVEID(raw); err == nil {
		return normalised
	}
	return strings.ToUpper(strings.TrimSpace(raw))
}

// buildAdvisoryUpdate turns the edited values into a patch, setting a pointer
// only for the fields whose value differs from the baseline. It also returns the
// names of the changed fields for the success panel.
func buildAdvisoryUpdate(in advisoryEditInput, baseline advisoryEditBaseline) (api.AdvisoryUpdatePatch, []string) {
	var patch api.AdvisoryUpdatePatch
	changes := make([]string, 0, 5)

	if summary := strings.TrimSpace(in.Summary); summary != baseline.summary {
		value := summary
		patch.Summary = &value
		changes = append(changes, "summary")
	}
	if description := strings.TrimSpace(in.Description); description != baseline.description {
		value := description
		patch.Description = &value
		changes = append(changes, "description")
	}
	if severity := in.Severity; severity.Valid() && severity != baseline.severity {
		value := severity
		patch.Severity = &value
		changes = append(changes, "severity")
	}
	if state := in.State; state.Editable() && state != baseline.state {
		value := state
		patch.State = &value
		changes = append(changes, "state")
	}
	if cveID := browseNormaliseCVEID(in.CVEID); !strings.EqualFold(cveID, baseline.cveID) {
		value := cveID
		patch.CVEID = &value
		changes = append(changes, "cve id")
	}

	return patch, changes
}
