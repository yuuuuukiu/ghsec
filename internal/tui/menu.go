package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/huh"
)

// ErrAborted is returned by every interactive helper when the user cancels the
// prompt (ctrl+c, esc where huh supports it, or a closed stdin). Callers must
// treat it as a graceful request to exit and must not write any configuration.
var ErrAborted = errors.New("aborted")

// Action is the top-level choice made in the main menu.
type Action int

// Main menu actions.
const (
	ActionReport Action = iota
	ActionAdvisory
	ActionBrowse
	ActionProfiles
	ActionQuit
)

// String implements fmt.Stringer so actions can be logged.
func (a Action) String() string {
	switch a {
	case ActionReport:
		return "report"
	case ActionAdvisory:
		return "advisory"
	case ActionBrowse:
		return "browse"
	case ActionProfiles:
		return "profiles"
	case ActionQuit:
		return "quit"
	default:
		return fmt.Sprintf("Action(%d)", int(a))
	}
}

// ProfAction is the choice made in the profile manager sub-menu.
type ProfAction int

// Profile manager actions.
const (
	ProfSwitch ProfAction = iota
	ProfAdd
	ProfDelete
	ProfBack
)

// String implements fmt.Stringer.
func (p ProfAction) String() string {
	switch p {
	case ProfSwitch:
		return "switch"
	case ProfAdd:
		return "add"
	case ProfDelete:
		return "delete"
	case ProfBack:
		return "back"
	default:
		return fmt.Sprintf("ProfAction(%d)", int(p))
	}
}

// Source describes where the advisory/report description text comes from.
type Source int

// Description sources.
const (
	SourceFile Source = iota
	SourceEditor
	SourceInline
)

// String implements fmt.Stringer.
func (s Source) String() string {
	switch s {
	case SourceFile:
		return "file"
	case SourceEditor:
		return "editor"
	case SourceInline:
		return "inline"
	default:
		return fmt.Sprintf("Source(%d)", int(s))
	}
}

// mapFormErr normalises an error returned by huh into either ErrAborted (the
// user cancelled) or a wrapped, human-readable failure. It never panics.
func mapFormErr(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, huh.ErrUserAborted),
		errors.Is(err, io.EOF),
		errors.Is(err, io.ErrUnexpectedEOF),
		errors.Is(err, context.Canceled):
		return ErrAborted
	}
	return fmt.Errorf("form: %w", err)
}

// runForm runs a form and maps its error through mapFormErr.
//
// The form is first prepared for the current terminal (see prepareForm) so a
// degenerate size such as 0x0 can never reach the rendering layer, and any
// residual panic from the TUI dependencies is converted into an error rather
// than terminating the process.
func runForm(f *huh.Form) error {
	safe, err := prepareForm(f)
	if err != nil {
		return err
	}
	return mapFormErr(runFormSafely(safe))
}

// noteSafe escapes the characters huh's note renderer treats as inline
// markdown, so literal text such as "public_repo" is shown verbatim.
func noteSafe(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\\', '_', '*', '`':
			b.WriteRune('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// identityLine renders the "signed in as ..." line shown above menus.
func identityLine(alias, username string) string {
	alias = strings.TrimSpace(alias)
	username = strings.TrimSpace(username)
	switch {
	case username != "" && alias != "":
		return fmt.Sprintf("Signed in as %s (profile: %s)", username, alias)
	case username != "":
		return fmt.Sprintf("Signed in as %s", username)
	case alias != "":
		return fmt.Sprintf("Signed in (profile: %s)", alias)
	default:
		return "Not signed in yet - add an API key to get started."
	}
}

// mainMenuDescription is the header copy shown on the main menu. The banner is
// printed once by main.go, so it is deliberately not repeated here: the menu is
// re-rendered in a loop and repeating it would flood the screen.
func mainMenuDescription(alias, username string) string {
	return strings.Join([]string{
		Accent(identityLine(alias, username)),
		Muted("Up/down to move, enter to choose, ctrl+c to quit."),
	}, "\n")
}

// newMainMenuForm builds the main menu without running it.
func newMainMenuForm(action *Action, alias, username string) *huh.Form {
	if action == nil {
		action = new(Action)
	}
	*action = ActionReport

	return huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[Action]().
				Title("What would you like to do?").
				Description(mainMenuDescription(alias, username)).
				Options(
					huh.NewOption("Submit a private vulnerability report", ActionReport),
					huh.NewOption("Create a security advisory draft (maintainer)", ActionAdvisory),
					huh.NewOption("Browse advisories, status & replies", ActionBrowse),
					huh.NewOption("Manage API keys / profiles", ActionProfiles),
					huh.NewOption("Exit", ActionQuit),
				).
				Value(action),
		),
	).WithTheme(Theme()).WithShowHelp(true)
}

// RunMainMenu asks the user what they want to do next.
func RunMainMenu(alias, username string) (Action, error) {
	action := ActionReport
	if err := runForm(newMainMenuForm(&action, alias, username)); err != nil {
		return ActionQuit, err
	}
	return action, nil
}

// profileMenuDescription summarises the configured profiles.
func profileMenuDescription(aliases []string, active string) string {
	active = strings.TrimSpace(active)
	var state string
	switch len(aliases) {
	case 0:
		state = "No profiles configured yet."
	case 1:
		state = "1 profile configured."
	default:
		state = fmt.Sprintf("%d profiles configured.", len(aliases))
	}
	if active == "" {
		state += " Active profile: " + Muted("none")
	} else {
		state += " Active profile: " + Accent(active)
	}
	return state
}

// newProfileMenuForm builds the profile manager menu without running it.
func newProfileMenuForm(action *ProfAction, aliases []string, active string) *huh.Form {
	if action == nil {
		action = new(ProfAction)
	}
	*action = ProfSwitch

	return huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[ProfAction]().
				Title("API keys / profiles").
				Description(profileMenuDescription(aliases, active)).
				Options(
					huh.NewOption("Switch active profile", ProfSwitch),
					huh.NewOption("Add a new profile", ProfAdd),
					huh.NewOption("Delete a profile", ProfDelete),
					huh.NewOption("Back to main menu", ProfBack),
				).
				Value(action),
		),
	).WithTheme(Theme()).WithShowHelp(true)
}

// RunProfileMenu asks what the user wants to do with their stored profiles.
func RunProfileMenu(aliases []string, active string) (ProfAction, error) {
	action := ProfSwitch
	if err := runForm(newProfileMenuForm(&action, aliases, active)); err != nil {
		return ProfBack, err
	}
	return action, nil
}

// profilePickerOptions labels every alias, marking the active one.
func profilePickerOptions(aliases []string, active string) []huh.Option[string] {
	active = strings.TrimSpace(active)
	opts := make([]huh.Option[string], 0, len(aliases))
	for _, alias := range aliases {
		label := alias
		if active != "" && alias == active {
			label += " \u2190 active"
		}
		opts = append(opts, huh.NewOption(label, alias))
	}
	return opts
}

// RunProfilePicker lets the user pick one of the stored profiles. It returns
// the chosen alias. An empty profile list is rejected before any TTY is
// touched so callers never block on a prompt that cannot be answered.
func RunProfilePicker(aliases []string, active string) (string, error) {
	if len(aliases) == 0 {
		return "", errors.New("no profiles available")
	}

	selected := strings.TrimSpace(active)
	if !containsString(aliases, selected) {
		selected = ""
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Select a profile").
				Description(profileMenuDescription(aliases, active)).
				Options(profilePickerOptions(aliases, active)...).
				Value(&selected),
		),
	).WithTheme(Theme()).WithShowHelp(true)

	if err := runForm(form); err != nil {
		return "", err
	}
	return selected, nil
}

// containsString reports whether want is present in values.
func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

// newDescriptionSourceForm builds the description-source picker.
func newDescriptionSourceForm(source *Source) *huh.Form {
	if source == nil {
		source = new(Source)
	}
	*source = SourceFile

	return huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[Source]().
				Title("How would you like to write the description?").
				Description(Muted("Markdown is supported by GitHub security advisories.")).
				Options(
					huh.NewOption("Read from a local file (Markdown/TXT)", SourceFile),
					huh.NewOption("Open my $EDITOR / $VISUAL", SourceEditor),
					huh.NewOption("Type or paste directly in the terminal", SourceInline),
				).
				Value(source),
		),
	).WithTheme(Theme()).WithShowHelp(true)
}

// RunDescriptionSource asks where the description body should come from.
func RunDescriptionSource() (Source, error) {
	source := SourceFile
	if err := runForm(newDescriptionSourceForm(&source)); err != nil {
		return SourceInline, err
	}
	return source, nil
}

// newConfirmForm builds a yes/no confirmation prompt.
func newConfirmForm(prompt string, value *bool) *huh.Form {
	return huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title(prompt).
				Affirmative("Yes").
				Negative("No").
				Value(value),
		),
	).WithTheme(Theme()).WithShowHelp(true)
}

// RunConfirm asks a yes/no question, defaulting to def.
func RunConfirm(prompt string, def bool) (bool, error) {
	value := def
	if err := runForm(newConfirmForm(prompt, &value)); err != nil {
		return false, err
	}
	return value, nil
}

// newNoteForm builds an informational note with a "Continue" button.
func newNoteForm(title, body string) *huh.Form {
	return huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title(title).
				Description(noteSafe(body)).
				Next(true).
				NextLabel("Continue"),
		),
	).WithTheme(Theme()).WithShowHelp(true)
}

// RunNote shows an informational note and returns once the user acknowledges
// it with enter.
func RunNote(title, body string) error {
	return runForm(newNoteForm(title, body))
}
