package tui

import (
	"strings"

	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/glamour/styles"

	"github.com/yukiu/ghsec/internal/api"
)

// defaultMDWidth is the wrap width used when a caller passes a
// non-positive width. glamour's own default is 80, which matches a classic
// 80-column terminal.
const defaultMDWidth = 80

// mdWidth normalises a terminal width into a usable glamour wrap width.
func mdWidth(width int) int {
	if width <= 0 {
		return defaultMDWidth
	}
	return width
}

// mdStripEscape removes ANSI escape sequences (CSI and OSC) from s, leaving the
// printable text. It is only used for blank-line detection, never for output.
func mdStripEscape(s string) string {
	if !strings.ContainsRune(s, 0x1b) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		if runes[i] != 0x1b {
			b.WriteRune(runes[i])
			continue
		}
		if i+1 >= len(runes) {
			break
		}
		switch runes[i+1] {
		case '[': // CSI: consume up to and including the final byte.
			i += 2
			for i < len(runes) && (runes[i] < 0x40 || runes[i] > 0x7e) {
				i++
			}
		case ']': // OSC: consume up to BEL or ST.
			i += 2
			for i < len(runes) && runes[i] != 0x07 {
				if runes[i] == 0x1b && i+1 < len(runes) && runes[i+1] == '\\' {
					i++
					break
				}
				i++
			}
		default: // Two-character escape.
			i++
		}
	}
	return b.String()
}

// mdBlankLine reports whether a line has no visible content once escape sequences
// are removed. glamour pads its output with styled spaces, so a plain
// strings.TrimSpace is not enough.
func mdBlankLine(line string) bool {
	return strings.TrimSpace(mdStripEscape(line)) == ""
}

// mdTrim removes the leading and trailing blank lines that glamour adds around
// its output (it pads with coloured spaces, and prefixes a blank line), so the
// rendered block composes tightly inside a panel.
func mdTrim(rendered string) string {
	lines := strings.Split(rendered, "\n")
	for len(lines) > 0 && mdBlankLine(lines[0]) {
		lines = lines[1:]
	}
	for len(lines) > 0 && mdBlankLine(lines[len(lines)-1]) {
		lines = lines[:len(lines)-1]
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n")
}

// newMarkdownRenderer builds a glamour renderer for the given width. Callers
// must treat a nil renderer as "render the raw markdown instead".
func newMDTermRenderer(width int) (*glamour.TermRenderer, error) {
	return glamour.NewTermRenderer(
		glamour.WithStandardStyle(styles.DarkStyle),
		glamour.WithWordWrap(mdWidth(width)),
	)
}

// RenderMarkdown renders md as styled terminal markdown wrapped to width.
//
// It never returns an error: if no renderer can be built or rendering fails,
// the raw markdown is returned unchanged. Markdown is treated purely as data —
// it is displayed, never interpreted — so arbitrary advisory text is safe to
// pass through here.
func RenderMarkdown(md string, width int) (out string) {
	if strings.TrimSpace(md) == "" {
		return ""
	}

	// A failed glamour render must not take the whole TUI down; fall back to the
	// plain source text.
	defer func() {
		if recover() != nil {
			out = md
		}
	}()

	renderer, err := newMDTermRenderer(width)
	if err != nil || renderer == nil {
		return md
	}
	rendered, err := renderer.Render(md)
	if err != nil {
		return md
	}
	return mdTrim(rendered)
}

// PreviewPanel renders markdown inside a titled box sized for width. The box
// chrome (borders and padding) takes four columns, so the markdown is wrapped
// slightly narrower than the requested width.
func PreviewPanel(title, markdown string, width int) string {
	inner := mdWidth(width) - 4
	if inner < 20 {
		inner = 20
	}

	body := RenderMarkdown(markdown, inner)
	if strings.TrimSpace(body) == "" {
		body = Muted("(nothing to preview)")
	}
	if strings.TrimSpace(title) == "" {
		title = "Preview"
	}
	return Box(title, body, colAccent)
}

// cardSeverity maps the advisory's string severity onto the typed severity used
// for colour coding. Unknown values are shown as a muted badge instead.
func resultCardSeverity(raw string) (api.Severity, bool) {
	sev, err := api.ParseSeverity(raw)
	if err != nil {
		return "", false
	}
	return sev, true
}

// resultCardRow renders one aligned label/value row, skipping empty values.
func resultCardRow(label, value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return KeyValue(label, value)
}

// resultCardBody assembles the shared rows for an advisory result card.
// An empty line or an empty row is omitted so the card stays compact.
func resultCardBody(a *api.Advisory, repoSpec string) string {
	lines := make([]string, 0, 8)

	if repo := strings.TrimSpace(repoSpec); repo != "" {
		lines = append(lines, resultCardRow("Repository", Accent(repo)))
	}
	lines = append(lines, resultCardRow("Advisory", Header(a.Identifier())))
	if sev, ok := resultCardSeverity(a.Severity); ok {
		// The badge already spells the level out; repeating the label next to it
		// renders "CRITICAL  Critical", so keep the badge only.
		lines = append(lines, resultCardRow("Severity", SeverityBadge(sev)))
	} else {
		lines = append(lines, resultCardRow("Severity", Muted("not set")))
	}
	if state := strings.TrimSpace(a.State); state != "" {
		lines = append(lines, resultCardRow("State", Badge(strings.ToUpper(state))))
	} else {
		lines = append(lines, resultCardRow("State", Muted("unknown")))
	}
	lines = append(lines, resultCardRow("CVE", a.CVEID))
	if summary := strings.TrimSpace(a.Summary); summary != "" {
		lines = append(lines, "")
		lines = append(lines, Muted("Summary"))
		lines = append(lines, summary)
	}
	if link := strings.TrimSpace(a.HTMLURL); link != "" {
		lines = append(lines, "")
		lines = append(lines, KeyValue("Open", Accent(link)))
	}

	return strings.Join(resultCardLines(lines), "\n")
}

// resultCardLines drops empty strings that came from skipped rows while keeping
// the deliberate blank separator lines.
func resultCardLines(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			// Keep a single blank line only when it sits between content rows.
			if len(out) == 0 || out[len(out)-1] == "" {
				continue
			}
		}
		out = append(out, line)
	}
	for len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	return out
}

// SuccessCard renders the result of a successful private report or advisory
// draft. It is nil-safe: when GitHub returns no advisory body the card explains
// that instead of panicking.
func SuccessCard(a *api.Advisory) string {
	if a == nil {
		return InfoPanel("No advisory details returned",
			"GitHub accepted the request but sent back no advisory details.\n"+
				Muted("Check the repository's Security tab to confirm the submission was recorded."))
	}

	title := "Submitted to GitHub"
	body := resultCardBody(a, "")
	if body == "" {
		body = Muted("The advisory was recorded, but no details were returned.")
	}
	return SuccessPanel(title, body)
}

// SuccessCardForRepo is SuccessCard, plus a line naming the repository the
// action was applied to.
func SuccessCardForRepo(a *api.Advisory, repoSpec string) string {
	if a == nil {
		body := "GitHub accepted the request but sent back no advisory details."
		if repo := strings.TrimSpace(repoSpec); repo != "" {
			body += "\n" + KeyValue("Repository", Accent(repo))
		}
		body += "\n" + Muted("Check the repository's Security tab to confirm the submission was recorded.")
		return InfoPanel("No advisory details returned", body)
	}

	title := "Submitted to GitHub"
	body := resultCardBody(a, repoSpec)
	if body == "" {
		body = Muted("The advisory was recorded, but no details were returned.")
	}
	return SuccessPanel(title, body)
}

// WelcomeCard renders the one-line profile summary shown above the main menu.
func WelcomeCard(alias, username string) string {
	alias = strings.TrimSpace(alias)
	username = strings.TrimSpace(username)

	if alias == "" {
		alias = "default"
	}

	handle := Muted("username not verified")
	if username != "" {
		handle = Accent("@" + username)
	}
	return Muted("Signed in as") + " " + Badge(alias) + " " + Muted("·") + " " + handle
}
