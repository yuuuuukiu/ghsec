package tui

import (
	"fmt"
	"os"

	"github.com/charmbracelet/huh"
	"golang.org/x/term"
)

// Terminal geometry limits.
//
// huh/bubbles compute a text input's inner width as
//
//	width - frameSize - promptWidth - 1
//
// for fields that set no CharLimit (the PAT input is one of them). When the
// terminal reports zero columns — a PTY with no window size, some CI runners,
// or a resize race — that value goes negative and bubbles panics inside
// make([]rune, width+1). These constants let us detect and neutralise that
// situation before handing control to huh.
const (
	// minUsableWidth is the narrowest terminal we will lay a form out in.
	minUsableWidth = 20
	// minUsableHeight is the shortest terminal we will lay a form out in.
	minUsableHeight = 8
	// fallbackFormWidth is used when the terminal reports no usable size at all.
	fallbackFormWidth = 80
	// fallbackFormHeight matches a classic 80x24 terminal.
	fallbackFormHeight = 24
)

// terminalSize returns the size of the terminal attached to stderr, which is
// where huh renders. It falls back to stdin and stdout because some
// environments only report a size for one of them.
func terminalSize() (width, height int, ok bool) {
	for _, f := range []*os.File{os.Stderr, os.Stdin, os.Stdout} {
		if f == nil {
			continue
		}
		w, h, err := term.GetSize(int(f.Fd()))
		if err == nil && w > 0 && h > 0 {
			return w, h, true
		}
	}
	return 0, 0, false
}

// prepareForm makes a form safe to run in the current terminal.
//
// It returns a possibly re-configured form, or an error when the terminal is too
// small to render a form readably (in which case nothing is drawn at all and the
// caller shows a friendly message instead of a crash).
func prepareForm(f *huh.Form) (*huh.Form, error) {
	if f == nil {
		return nil, fmt.Errorf("form: internal error: nil form")
	}

	width, height, ok := terminalSize()
	switch {
	case !ok:
		// No reported size (0x0 PTY, redirected device, resize race). Pin a
		// classic 80x24 layout so huh never divides the width down to a
		// negative value. Pinning f.width also stops huh from overwriting the
		// layout from a subsequent zero-valued WindowSizeMsg.
		return f.WithWidth(fallbackFormWidth).WithHeight(fallbackFormHeight), nil
	case width < minUsableWidth || height < minUsableHeight:
		return nil, fmt.Errorf(
			"the terminal is too small (%dx%d): resize the window to at least %dx%d and try again",
			width, height, minUsableWidth, minUsableHeight)
	default:
		return f, nil
	}
}

// runFormSafely runs a form and converts any panic raised by the TUI libraries
// into an ordinary error, so a rendering bug in a dependency can never take the
// whole program (and the user's terminal state) down with it.
func runFormSafely(f *huh.Form) error {
	return safeCall(f.Run)
}

// safeCall runs fn, converting any panic into an ordinary error.
//
// It is separate from runFormSafely so the recovery behaviour can be tested
// without starting a real form: running one would attach to the terminal and
// block forever on Windows, where the console read does not return EOF the way
// a redirected stdin does on Unix.
func safeCall(fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("this screen could not be rendered in the current terminal: %v "+
				"(try resizing the window or running in a different terminal)", r)
		}
	}()
	return fn()
}
