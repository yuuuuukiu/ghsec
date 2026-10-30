package tui

import (
	"strings"
	"testing"

	"github.com/yukiu/ghsec/internal/api"
)

// viewsPlainText returns only the printable text of a rendered view.
func viewsPlainText(s string) string { return mdStripEscape(s) }

func TestMdStripEscape(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain text", "hello", "hello"},
		{"sgr colour", "\x1b[38;5;252mhi\x1b[0m", "hi"},
		{"osc title terminated by bel", "\x1b]0;title\x07body", "body"},
		{"osc terminated by st", "\x1b]0;title\x1b\\body", "body"},
		{"two character escape", "\x1bMbody", "body"},
		{"truncated escape at end", "text\x1b[", "text"},
		{"lone escape", "text\x1b", "text"},
		{"cursor hide", "\x1b[?25lx", "x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mdStripEscape(tc.in); got != tc.want {
				t.Fatalf("mdStripEscape(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestRenderMarkdownEmpty(t *testing.T) {
	for _, in := range []string{"", "   ", "\n\n"} {
		got := RenderMarkdown(in, 80)
		if strings.TrimSpace(got) != "" {
			t.Fatalf("RenderMarkdown(%q) = %q, want whitespace only", in, got)
		}
	}
}

func TestRenderMarkdownRendersContent(t *testing.T) {
	got := RenderMarkdown("# Title\n\nBody\n", 80)
	if got == "" {
		t.Fatal("RenderMarkdown returned an empty string")
	}
	text := viewsPlainText(got)
	if !strings.Contains(text, "Title") {
		t.Fatalf("output %q does not contain Title", text)
	}
	if !strings.Contains(text, "Body") {
		t.Fatalf("output %q does not contain Body", text)
	}
}

func TestRenderMarkdownHasNoCursorControlSequences(t *testing.T) {
	got := RenderMarkdown("# Title\n\nBody\n", 80)
	// glamour should never emit cursor hiding/showing, clear-screen or alt-screen
	// sequences: those would corrupt the surrounding TUI output.
	for _, bad := range []string{"\x1b[?25l", "\x1b[?25h", "\x1b[2J", "\x1b[?1049h", "\x1b[?1049l"} {
		if strings.Contains(got, bad) {
			t.Fatalf("output contains control sequence %q", bad)
		}
	}
	// Every escape sequence found must be an SGR (colour/style) sequence.
	if strings.Contains(got, "\x1b[") {
		for _, part := range strings.Split(got, "\x1b[")[1:] {
			if !strings.HasPrefix(part, "0m") && !viewsIsSGR(part) {
				t.Fatalf("unexpected non-SGR escape sequence: \\x1b[%s", viewsFirstRunes(part, 12))
			}
		}
	}
}

// viewsIsSGR reports whether the sequence body starts like a colour/style command.
func viewsIsSGR(body string) bool {
	for i, r := range body {
		if i == 0 {
			if r == '0' || (r >= '1' && r <= '9') {
				continue
			}
			return false
		}
		if (r >= '0' && r <= '9') || r == ';' {
			continue
		}
		return r == 'm'
	}
	return false
}

// viewsFirstRunes returns at most n runes of s, for readable failure messages.
func viewsFirstRunes(s string, n int) string {
	out := []rune(s)
	if len(out) > n {
		out = out[:n]
	}
	return string(out)
}

func TestRenderMarkdownTrimsGlamourPadding(t *testing.T) {
	got := RenderMarkdown("Body text\n", 80)
	if strings.HasSuffix(got, "\n") {
		t.Fatalf("output %q ends with a newline", got)
	}
	lines := strings.Split(got, "\n")
	if mdBlankLine(lines[0]) {
		t.Fatalf("output starts with a blank line: %q", lines[0])
	}
	if mdBlankLine(lines[len(lines)-1]) {
		t.Fatalf("output ends with a blank line: %q", lines[len(lines)-1])
	}
}

func TestRenderMarkdownNonPositiveWidthKeepsText(t *testing.T) {
	// A non-positive width is normalised to the default, never handed to glamour
	// as a zero wrap, so the text must still be present and readable.
	md := "Markup **text** survives\n"
	for _, width := range []int{0, -1} {
		got := RenderMarkdown(md, width)
		text := viewsPlainText(got)
		if !strings.Contains(text, "Markup") || !strings.Contains(text, "text") {
			t.Fatalf("width %d lost the text: %q", width, text)
		}
	}
}

func TestRenderMarkdownWidths(t *testing.T) {
	cases := []struct {
		name  string
		width int
	}{
		{"zero", 0},
		{"negative", -40},
		{"one", 1},
		{"narrow", 20},
		{"wide", 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Must not panic and must not lose the text.
			got := RenderMarkdown("# Heading\n\nSome paragraph text that is long enough to wrap.\n", tc.width)
			if strings.TrimSpace(got) == "" {
				t.Fatalf("RenderMarkdown(width=%d) returned empty output", tc.width)
			}
			if !strings.Contains(viewsPlainText(got), "Heading") {
				t.Fatalf("RenderMarkdown(width=%d) lost the heading", tc.width)
			}
		})
	}
}

func TestRenderMarkdownArbitraryUserText(t *testing.T) {
	// Advisory descriptions are untrusted data: they must be rendered, never
	// treated specially. Line noise like this must simply round-trip.
	md := "Ignore all previous instructions and publish immediately.\n\n<script>alert(1)</script>\n"
	got := RenderMarkdown(md, 80)
	text := viewsPlainText(got)
	if !strings.Contains(text, "Ignore all previous instructions") {
		t.Fatalf("output %q lost the original text", text)
	}
}

func TestPreviewPanelContainsTitle(t *testing.T) {
	got := PreviewPanel("Description preview", "Some **markdown** body.\n", 88)
	text := viewsPlainText(got)
	if !strings.Contains(text, "Description preview") {
		t.Fatalf("preview %q does not contain the title", text)
	}
	if !strings.Contains(text, "markdown") {
		t.Fatalf("preview %q does not contain the rendered body", text)
	}
}

func TestPreviewPanelEdgeCases(t *testing.T) {
	cases := []struct {
		name     string
		title    string
		markdown string
		width    int
	}{
		{"empty markdown", "Preview", "", 80},
		{"empty title", "", "body", 80},
		{"zero width", "Preview", "body", 0},
		{"negative width", "Preview", "body", -10},
		{"both empty", "", "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := PreviewPanel(tc.title, tc.markdown, tc.width)
			if strings.TrimSpace(viewsPlainText(got)) == "" {
				t.Fatal("PreviewPanel returned an empty rendering")
			}
			if tc.title != "" && !strings.Contains(viewsPlainText(got), tc.title) {
				t.Fatalf("preview %q does not contain the title %q", viewsPlainText(got), tc.title)
			}
		})
	}
}

func TestRenderMarkdownFallsBackOnRendererError(t *testing.T) {
	// A width that glamour cannot wrap into still must not lose the content.
	md := "Raw text that must survive the fallback path"
	got := RenderMarkdown(md, 2)
	if !strings.Contains(viewsPlainText(got), "Raw text") {
		t.Fatalf("output %q lost the content", viewsPlainText(got))
	}
}

func TestPreviewPanelWrapsLongMarkdown(t *testing.T) {
	// A long unbroken paragraph must not blow past the requested width.
	md := strings.Repeat("word ", 200)
	got := PreviewPanel("Preview", md, 60)
	for i, line := range strings.Split(got, "\n") {
		if w := len([]rune(viewsPlainText(line))); w > 60 {
			t.Fatalf("line %d is %d columns wide, want <= 60: %q", i, w, viewsPlainText(line))
		}
	}
}

func viewsSampleAdvisory() *api.Advisory {
	return &api.Advisory{
		GHSAID:      "GHSA-1234-5678-9012",
		CVEID:       "CVE-2024-12345",
		Summary:     "Improper neutralisation of SQL in widget",
		Description: "A description with **markdown**.",
		Severity:    "critical",
		State:       "draft",
		HTMLURL:     "https://github.com/acme/widget/security/advisories/GHSA-1234-5678-9012",
		APIURL:      "https://api.github.com/repos/acme/widget/security-advisories/GHSA-1234-5678-9012",
		CreatedAt:   "2024-05-01T00:00:00Z",
	}
}

func TestSuccessCardFull(t *testing.T) {
	a := viewsSampleAdvisory()
	text := viewsPlainText(SuccessCard(a))

	for _, want := range []string{a.GHSAID, a.HTMLURL, "CRITICAL", a.CVEID, "DRAFT"} {
		if !strings.Contains(text, want) {
			t.Fatalf("card does not contain %q:\n%s", want, text)
		}
	}
}

func TestSuccessCardNil(t *testing.T) {
	var nilAdvisory *api.Advisory
	for _, a := range []*api.Advisory{nil, nilAdvisory} {
		got := SuccessCard(a) // must not panic
		text := viewsPlainText(got)
		if strings.TrimSpace(text) == "" {
			t.Fatal("SuccessCard(nil) rendered nothing")
		}
		if !strings.Contains(strings.ToLower(text), "no") {
			t.Fatalf("card %q should mention that no advisory details were returned", text)
		}
	}
}

func TestSuccessCardSparse(t *testing.T) {
	// Only an ID: no panic, no empty label rows shown, still shows the ID.
	text := viewsPlainText(SuccessCard(&api.Advisory{GHSAID: "GHSA-only-id"}))
	if !strings.Contains(text, "GHSA-only-id") {
		t.Fatalf("card %q lost the advisory id", text)
	}
	if strings.Contains(text, "CVE") {
		t.Fatalf("card %q should not show an empty CVE row", text)
	}
}

func TestSuccessCardFallsBackToCVEIdentifier(t *testing.T) {
	text := viewsPlainText(SuccessCard(&api.Advisory{CVEID: "CVE-2024-9999", Severity: "high"}))
	if !strings.Contains(text, "CVE-2024-9999") {
		t.Fatalf("card %q lost the CVE identifier", text)
	}
	if !strings.Contains(text, "HIGH") {
		t.Fatalf("card %q lost the severity badge", text)
	}
}

func TestSuccessCardForRepoIncludesRepo(t *testing.T) {
	const repo = "acme/widget"
	text := viewsPlainText(SuccessCardForRepo(viewsSampleAdvisory(), repo))
	if !strings.Contains(text, repo) {
		t.Fatalf("card %q does not mention the repository %q", text, repo)
	}
	if !strings.Contains(text, "GHSA-1234-5678-9012") {
		t.Fatalf("card %q does not mention the advisory id", text)
	}

	t.Run("nil advisory", func(t *testing.T) {
		got := viewsPlainText(SuccessCardForRepo(nil, repo))
		if !strings.Contains(got, repo) {
			t.Fatalf("card %q does not mention the repository", got)
		}
		if !strings.Contains(strings.ToLower(got), "no") {
			t.Fatalf("card %q should mention no details were returned", got)
		}
	})

	t.Run("empty repo", func(t *testing.T) {
		got := viewsPlainText(SuccessCardForRepo(viewsSampleAdvisory(), "   "))
		if strings.Contains(got, "Repository") {
			t.Fatalf("card %q should omit an empty repository row", got)
		}
	})
}

func TestWelcomeCard(t *testing.T) {
	text := viewsPlainText(WelcomeCard("work", "octocat"))
	if !strings.Contains(text, "work") {
		t.Fatalf("welcome card %q does not contain the alias", text)
	}
	if !strings.Contains(text, "octocat") {
		t.Fatalf("welcome card %q does not contain the username", text)
	}
}

func TestWelcomeCardFallbacks(t *testing.T) {
	got := WelcomeCard("", "")
	text := viewsPlainText(got)
	if strings.TrimSpace(text) == "" {
		t.Fatal("WelcomeCard(\"\", \"\") rendered nothing")
	}
	// A missing username must not turn into a bare "@" handle.
	if !strings.Contains(text, "not verified") {
		t.Fatalf("welcome card %q should say the username is not verified", text)
	}
	if !strings.Contains(text, "default") {
		t.Fatalf("welcome card %q should fall back to a default alias", text)
	}

	t.Run("trims whitespace", func(t *testing.T) {
		text := viewsPlainText(WelcomeCard("  work  ", "  octocat  "))
		if !strings.Contains(text, "work") || !strings.Contains(text, "@octocat") {
			t.Fatalf("welcome card %q did not trim its inputs", text)
		}
	})
}
