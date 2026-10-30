// Package tui contains every terminal-facing interaction: themed forms, menus,
// markdown previews and status panels.
package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"

	"github.com/yuuuuukiu/ghsec/internal/api"
)

// Colour palette. Chosen for contrast on both dark and light terminals.
var (
	colPrimary = lipgloss.Color("#7D56F4") // violet
	colAccent  = lipgloss.Color("#00D7FF") // cyan
	colOK      = lipgloss.Color("#3DD68C") // green
	colWarn    = lipgloss.Color("#FFB454") // amber
	colErr     = lipgloss.Color("#FF5F87") // red
	colMuted   = lipgloss.Color("#7A7A7A")

	colCritical = lipgloss.Color("#FF3B30")
	colHigh     = lipgloss.Color("#FF7A45")
	colMedium   = lipgloss.Color("#FFC53D")
	colLow      = lipgloss.Color("#4FC3F7")
)

var (
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(colPrimary)
	accentStyle = lipgloss.NewStyle().Foreground(colAccent)
	mutedStyle  = lipgloss.NewStyle().Foreground(colMuted)
	okStyle     = lipgloss.NewStyle().Foreground(colOK).Bold(true)
	warnStyle   = lipgloss.NewStyle().Foreground(colWarn).Bold(true)
	errStyle    = lipgloss.NewStyle().Foreground(colErr).Bold(true)
	okMark      = lipgloss.NewStyle().Foreground(colOK)
	errMark     = lipgloss.NewStyle().Foreground(colErr)
)

// Box draws a rounded panel with a coloured border and title.
func Box(title, body string, border lipgloss.Color) string {
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(border).
		Padding(0, 1)

	if strings.TrimSpace(title) == "" {
		return box.Render(body)
	}
	header := lipgloss.NewStyle().Bold(true).Foreground(border).Render("▸ " + title)
	return box.Render(header + "\n" + body)
}

// SuccessPanel renders a green success box with a check glyph.
func SuccessPanel(title, body string) string {
	return Box("✅  "+title, body, colOK)
}

// ErrorPanel renders a red error box with a cross glyph.
func ErrorPanel(title, body string) string {
	return Box("⛔  "+title, body, colErr)
}

// WarnPanel renders an amber warning box.
func WarnPanel(title, body string) string {
	return Box("⚠️   "+title, body, colWarn)
}

// InfoPanel renders a neutral informational box.
func InfoPanel(title, body string) string {
	return Box("ℹ️   "+title, body, colAccent)
}

// Header renders a bold section header.
func Header(text string) string {
	return titleStyle.Render(text)
}

// KeyValue renders an aligned "label  value" line.
func KeyValue(label, value string) string {
	lbl := lipgloss.NewStyle().
		Foreground(colMuted).
		Width(14).
		Render(label)
	return lbl + " " + value
}

// Muted dims helper text.
func Muted(s string) string { return mutedStyle.Render(s) }

// Dim is an alias of Muted kept for call-site readability.
func Dim(s string) string { return mutedStyle.Render(s) }

// Badge renders an inverted chip, useful for the active profile marker.
func Badge(text string) string {
	return lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(colPrimary).
		Padding(0, 1).
		Render(text)
}

// SeverityBadge renders a colour-coded severity chip.
func SeverityBadge(sev api.Severity) string {
	color := colMuted
	switch sev {
	case api.SeverityCritical:
		color = colCritical
	case api.SeverityHigh:
		color = colHigh
	case api.SeverityMedium:
		color = colMedium
	case api.SeverityLow:
		color = colLow
	}
	return lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(color).
		Padding(0, 1).
		Render(strings.ToUpper(string(sev)))
}

// StateBadge renders a colour-coded advisory lifecycle state chip so the
// browser can show "draft" / "triage" / "published" / "closed" at a glance.
func StateBadge(state api.AdvisoryState) string {
	color := colMuted
	switch state {
	case api.StateDraft:
		color = colAccent
	case api.StateTriage:
		color = colWarn
	case api.StatePublished:
		color = colOK
	case api.StateClosed:
		color = colMuted
	}
	label := state.Label()
	if label == "" {
		label = "unknown"
	}
	return lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(color).
		Padding(0, 1).
		Render(strings.ToUpper(label))
}

// Banner renders the application header shown at the top of each screen.
func Banner() string {
	art := []string{
		"  ██████╗ ██╗  ██╗███████╗███████╗ ██████╗",
		" ██╔════╝ ██║  ██║██╔════╝██╔════╝██╔════╝",
		" ██║  ███╗███████║███████╗█████╗  ██║     ",
		" ██║   ██║██╔══██║╚════██║██╔══╝  ██║     ",
		" ╚██████╔╝██║  ██║███████║███████╗╚██████╗",
		"  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝",
	}
	logo := lipgloss.NewStyle().Foreground(colPrimary).Bold(true).Render(strings.Join(art, "\n"))
	tag := mutedStyle.Render("  GitHub Security Advisories, from your terminal")
	return logo + "\n" + tag
}

// Theme returns the ghsec huh theme (form fields, inputs, selects).
func Theme() *huh.Theme {
	t := huh.ThemeBase()

	t.Focused.Title = lipgloss.NewStyle().Bold(true).Foreground(colPrimary)
	t.Focused.Description = mutedStyle
	t.Focused.ErrorIndicator = errStyle
	t.Focused.ErrorMessage = errStyle.SetString("✖ ")
	t.Focused.SelectSelector = lipgloss.NewStyle().Foreground(colAccent).SetString("❯ ")
	t.Focused.NextIndicator = lipgloss.NewStyle().Foreground(colAccent).SetString(" ↓")
	t.Focused.PrevIndicator = lipgloss.NewStyle().Foreground(colAccent).SetString(" ↑")
	t.Focused.Option = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#333333", Dark: "#DDDDDD"})
	t.Focused.MultiSelectSelector = lipgloss.NewStyle().Foreground(colAccent).SetString("❯ ")
	t.Focused.SelectedOption = lipgloss.NewStyle().Foreground(colOK)
	t.Focused.SelectedPrefix = lipgloss.NewStyle().Foreground(colOK).SetString("✓ ")
	t.Focused.UnselectedPrefix = lipgloss.NewStyle().Foreground(colMuted).SetString("• ")
	t.Focused.UnselectedOption = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#333333", Dark: "#DDDDDD"})
	t.Focused.FocusedButton = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(colPrimary).
		Bold(true).
		Padding(0, 1)
	t.Focused.BlurredButton = lipgloss.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "#333333", Dark: "#DDDDDD"}).
		Padding(0, 1)
	t.Focused.TextInput.Cursor = lipgloss.NewStyle().Foreground(colAccent)
	t.Focused.TextInput.Placeholder = mutedStyle
	t.Focused.TextInput.Prompt = lipgloss.NewStyle().Foreground(colAccent)
	t.Focused.NoteTitle = lipgloss.NewStyle().Bold(true).Foreground(colPrimary).MarginBottom(1)

	t.Blurred = t.Focused
	t.Blurred.Title = mutedStyle.Bold(true)
	t.Blurred.Description = mutedStyle
	t.Blurred.SelectSelector = lipgloss.NewStyle().Foreground(colMuted).SetString("  ")
	t.Blurred.TextInput.Prompt = lipgloss.NewStyle().Foreground(colMuted)

	t.Group.Title = lipgloss.NewStyle().Bold(true).Foreground(colPrimary)
	t.Group.Description = mutedStyle

	t.FieldSeparator = lipgloss.NewStyle().Foreground(colMuted)
	t.Help.Ellipsis = mutedStyle
	t.Help.ShortKey = lipgloss.NewStyle().Foreground(colAccent)
	t.Help.ShortDesc = mutedStyle
	t.Help.ShortSeparator = mutedStyle.SetString(" • ")
	t.Help.FullKey = lipgloss.NewStyle().Foreground(colAccent)
	t.Help.FullDesc = mutedStyle
	t.Help.FullSeparator = mutedStyle.SetString(" • ")

	return t
}

// divider renders a dim horizontal rule sized to width.
func divider(width int) string {
	if width <= 0 {
		width = 48
	}
	if width > 120 {
		width = 120
	}
	return mutedStyle.Render(strings.Repeat("─", width))
}

// spaced joins non-empty parts with a dim separator.
func spaced(parts ...string) string {
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, mutedStyle.Render("  ·  "))
}

// Errorf renders a red error line without a panel.
func Errorf(format string, args ...any) string {
	return errMark.Render(fmt.Sprintf(format, args...))
}

// Successf renders a green success line.
func Successf(format string, args ...any) string {
	return okMark.Render(fmt.Sprintf(format, args...))
}

// Warnf renders an amber warning line.
func Warnf(format string, args ...any) string {
	return warnStyle.Render(fmt.Sprintf(format, args...))
}

// Okf is an alias for Successf for brevity at call sites.
func Okf(format string, args ...any) string { return Successf(format, args...) }

// Accent highlights a value in cyan.
func Accent(s string) string { return accentStyle.Render(s) }

// compile-time guards so unused-but-intentional helpers do not drift.
var _ = []any{divider, spaced, Errorf, Warnf, Accent, InfoPanel, WarnPanel, SeverityBadge, Banner, Header, KeyValue, Muted, Badge, Okf}
