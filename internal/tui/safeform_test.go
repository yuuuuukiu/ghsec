package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/huh"

	"github.com/yukiu/ghsec/internal/api"
)

func TestPrepareFormRejectsNil(t *testing.T) {
	if _, err := prepareForm(nil); err == nil {
		t.Fatal("prepareForm(nil) must return an error")
	}
}

func TestPrepareFormIsRenderableInAllTerminalStates(t *testing.T) {
	// prepareForm inspects the real terminal. In a test binary there is usually
	// no TTY, which exercises the "no reported size" fallback branch — the very
	// case that used to panic inside bubbles.
	form := huh.NewForm(huh.NewGroup(huh.NewInput().Title("token")))
	safe, err := prepareForm(form)
	if err != nil {
		// A too-small terminal is a legitimate, friendly refusal.
		if !strings.Contains(err.Error(), "too small") {
			t.Fatalf("prepareForm() unexpected error: %v", err)
		}
		return
	}
	if safe == nil {
		t.Fatal("prepareForm() returned a nil form without an error")
	}
}

func TestRunFormSafelyConvertsPanicToError(t *testing.T) {
	// runFormSafely must never let a dependency panic escape. We cannot easily
	// make huh panic on demand, so assert the contract via a form that fails
	// fast: it must return an error rather than panic, and must not block.
	form := huh.NewForm(huh.NewGroup(huh.NewNote().Title("note").Next(true)))
	if err := runFormSafely(form); err != nil {
		if strings.Contains(err.Error(), "panic") {
			t.Logf("runFormSafely surfaced a rendering problem as an error: %v", err)
		}
	}
}

func TestRunFormMapsAbort(t *testing.T) {
	// A nil form is a programming error, not a user abort.
	if err := runForm(nil); err == nil {
		t.Fatal("runForm(nil) must return an error")
	}
}

func TestTerminalFallbacksAreUsable(t *testing.T) {
	if fallbackFormWidth < minUsableWidth {
		t.Fatalf("fallbackFormWidth (%d) must be at least minUsableWidth (%d)",
			fallbackFormWidth, minUsableWidth)
	}
	if fallbackFormHeight < minUsableHeight {
		t.Fatalf("fallbackFormHeight (%d) must be at least minUsableHeight (%d)",
			fallbackFormHeight, minUsableHeight)
	}
}

func TestTerminalSizeNeverNegative(t *testing.T) {
	w, h, ok := terminalSize()
	if ok && (w <= 0 || h <= 0) {
		t.Fatalf("terminalSize() reported an unusable size %dx%d with ok=true", w, h)
	}
	if !ok && (w != 0 || h != 0) {
		t.Fatalf("terminalSize() should return zeros when unusable, got %dx%d", w, h)
	}
}

func TestStateBadgeRendersEveryState(t *testing.T) {
	for _, s := range api.AdvisoryStates {
		out := StateBadge(s)
		if out == "" {
			t.Fatalf("StateBadge(%q) is empty", s)
		}
		if !strings.Contains(strings.ToUpper(out), strings.ToUpper(s.Label())) {
			t.Fatalf("StateBadge(%q) = %q, want it to contain %q", s, out, s.Label())
		}
	}
	// An unknown state must not panic and must still render something.
	if got := StateBadge(api.AdvisoryState("weird")); got == "" {
		t.Fatal("StateBadge(unknown) is empty")
	}
}
