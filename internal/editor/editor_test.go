package editor

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeScript drops an executable shell script into dir and returns its path.
func writeScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatalf("chmod script: %v", err)
	}
	return path
}

func TestResolveEditorPrecedence(t *testing.T) {
	t.Run("visual wins", func(t *testing.T) {
		t.Setenv("VISUAL", "visual-editor")
		t.Setenv("EDITOR", "editor-editor")
		ed := ResolveEditor()
		if ed.Name != "visual-editor" {
			t.Fatalf("Name = %q, want visual-editor", ed.Name)
		}
		if ed.Source != "$VISUAL" {
			t.Fatalf("Source = %q, want $VISUAL", ed.Source)
		}
	})

	t.Run("editor when visual empty", func(t *testing.T) {
		t.Setenv("VISUAL", "")
		t.Setenv("EDITOR", "myeditor")
		ed := ResolveEditor()
		if ed.Name != "myeditor" {
			t.Fatalf("Name = %q, want myeditor", ed.Name)
		}
		if ed.Source != "$EDITOR" {
			t.Fatalf("Source = %q, want $EDITOR", ed.Source)
		}
	})

	t.Run("default when both empty", func(t *testing.T) {
		t.Setenv("VISUAL", "")
		t.Setenv("EDITOR", "")
		ed := ResolveEditor()
		if ed.Source != "default" {
			t.Fatalf("Source = %q, want default", ed.Source)
		}
		if strings.TrimSpace(ed.Name) == "" {
			t.Fatal("ResolveEditor returned an empty Name")
		}
		if runtime.GOOS == "windows" && ed.Name != "notepad" {
			t.Fatalf("Name = %q, want notepad on windows", ed.Name)
		}
	})
}

func TestResolveEditorParsesFlags(t *testing.T) {
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "myeditor --wait")
	ed := ResolveEditor()
	if ed.Name != "myeditor" {
		t.Fatalf("Name = %q, want myeditor", ed.Name)
	}
	if len(ed.Args) != 1 || ed.Args[0] != "--wait" {
		t.Fatalf("Args = %#v, want [--wait]", ed.Args)
	}
	if ed.Source != "$EDITOR" {
		t.Fatalf("Source = %q, want $EDITOR", ed.Source)
	}

	t.Run("multiple flags", func(t *testing.T) {
		t.Setenv("EDITOR", "  vim   -n  -u NONE ")
		ed := ResolveEditor()
		if ed.Name != "vim" {
			t.Fatalf("Name = %q, want vim", ed.Name)
		}
		if len(ed.Args) != 3 || ed.Args[0] != "-n" || ed.Args[1] != "-u" || ed.Args[2] != "NONE" {
			t.Fatalf("Args = %#v, want [-n -u NONE]", ed.Args)
		}
	})

	t.Run("whitespace only is ignored", func(t *testing.T) {
		t.Setenv("EDITOR", "   ")
		ed := ResolveEditor()
		if ed.Source != "default" {
			t.Fatalf("Source = %q, want default", ed.Source)
		}
	})
}

func TestResolveEditorHandlesPathWithSpaces(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script based test")
	}
	dir := t.TempDir()
	spacedDir := filepath.Join(dir, "my editors")
	if err := os.MkdirAll(spacedDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	script := writeScript(t, spacedDir, "spaced.sh", `:`)

	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", script)
	ed := ResolveEditor()
	// The whole value names an existing executable, so it must not be split on
	// its spaces; this is the documented best-effort behaviour.
	if ed.Name != script {
		t.Fatalf("Name = %q, want %q", ed.Name, script)
	}
	if len(ed.Args) != 0 {
		t.Fatalf("Args = %#v, want none", ed.Args)
	}
}

func TestOpenWithAppendsAndCleansUp(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script based test")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "marker.txt")
	script := writeScript(t, dir, "fake-editor.sh",
		`printf '%s\n' "$1" > "$GHSEC_TEST_MARKER"`+"\n"+
			`printf 'appended by editor\n' >> "$1"`)

	t.Setenv("GHSEC_TEST_MARKER", marker)

	got, err := OpenWith(Editor{Name: script, Source: "$EDITOR"}, "initial description\n")
	if err != nil {
		t.Fatalf("OpenWith returned error: %v", err)
	}
	if !strings.Contains(got, "initial description") {
		t.Fatalf("content %q missing initial text", got)
	}
	if !strings.Contains(got, "appended by editor") {
		t.Fatalf("content %q missing appended text", got)
	}

	// The editor saw exactly one argument and it was a real file.
	raw, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	editedPath := strings.TrimSpace(string(raw))
	if editedPath == "" {
		t.Fatal("editor did not report the file path it was given")
	}
	if !strings.HasSuffix(editedPath, ".md") {
		t.Fatalf("temp file %q does not end in .md", editedPath)
	}
	if !strings.Contains(filepath.Base(editedPath), tempPrefix) {
		t.Fatalf("temp file %q does not use prefix %q", editedPath, tempPrefix)
	}

	// The temp file must be gone once OpenWith returns.
	if _, err := os.Stat(editedPath); !os.IsNotExist(err) {
		t.Fatalf("temp file %q was not removed (stat err = %v)", editedPath, err)
	}
}

func TestOpenUsesResolvedEditor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script based test")
	}
	dir := t.TempDir()
	script := writeScript(t, dir, "visual-editor.sh",
		`printf 'from $VISUAL\n' >> "$1"`)

	// $VISUAL must win over $EDITOR and be the command that actually runs.
	t.Setenv("VISUAL", script)
	t.Setenv("EDITOR", "this-editor-must-not-run")

	got, err := Open("starting content\n")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !strings.Contains(got, "starting content") || !strings.Contains(got, "from $VISUAL") {
		t.Fatalf("content %q did not come from the $VISUAL editor", got)
	}
}

func TestOpenWithFailingEditorKeepsContent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script based test")
	}
	dir := t.TempDir()
	script := writeScript(t, dir, "failing-editor.sh",
		`printf 'edits made before failure\n' >> "$1"`+"\n"+`exit 3`)

	got, err := OpenWith(Editor{Name: script}, "original text\n")
	if err == nil {
		t.Fatal("expected an error when the editor exits non-zero")
	}
	if !strings.Contains(err.Error(), "status 3") {
		t.Fatalf("error %q should mention exit status 3", err)
	}
	if !strings.Contains(err.Error(), script) && !strings.Contains(err.Error(), filepath.Base(script)) {
		t.Fatalf("error %q should mention the editor name", err)
	}
	if !strings.Contains(got, "original text") || !strings.Contains(got, "edits made before failure") {
		t.Fatalf("content %q lost the user's work", got)
	}
}

func TestOpenWithMissingEditor(t *testing.T) {
	_, err := OpenWith(Editor{Name: "ghsec-editor-that-does-not-exist"}, "x")
	if err == nil {
		t.Fatal("expected an error for a missing editor")
	}
	if !strings.Contains(err.Error(), "ghsec-editor-that-does-not-exist") {
		t.Fatalf("error %q should name the missing editor", err)
	}
}

func TestOpenWithPassesArgsBeforePath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script based test")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "args.txt")
	script := writeScript(t, dir, "args-editor.sh",
		`printf '%s\n' "$@" > "$GHSEC_ARGS_MARKER"`)

	t.Setenv("GHSEC_ARGS_MARKER", marker)

	if _, err := OpenWith(Editor{Name: script, Args: []string{"--wait", "-n"}}, "x"); err != nil {
		t.Fatalf("OpenWith: %v", err)
	}

	raw, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	args := strings.Fields(string(raw))
	if len(args) != 3 {
		t.Fatalf("editor received %d args (%q), want 3", len(args), args)
	}
	if args[0] != "--wait" || args[1] != "-n" {
		t.Fatalf("flags were not passed before the path: %q", args)
	}
	if !strings.HasSuffix(args[2], tempSuffix) {
		t.Fatalf("last argument %q should be the temp file path", args[2])
	}
}

func TestOpenWithTempFileIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script based test")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "mode.txt")
	// GNU stat uses -c, BSD stat uses -f; try both.
	script := writeScript(t, dir, "mode-editor.sh",
		`(stat -f '%Lp' "$1" 2>/dev/null || stat -c '%a' "$1" 2>/dev/null) > "$GHSEC_MODE_MARKER"`)

	t.Setenv("GHSEC_MODE_MARKER", marker)

	if _, err := OpenWith(Editor{Name: script}, "secret vulnerability\n"); err != nil {
		t.Fatalf("OpenWith: %v", err)
	}

	raw, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	mode := strings.TrimSpace(string(raw))
	if mode == "" {
		t.Skip("stat is unavailable in this environment")
	}
	if mode != "600" {
		t.Fatalf("temp file mode = %q, want 600", mode)
	}
}

func TestOpenWithEmptyInitialContent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script based test")
	}
	dir := t.TempDir()
	script := writeScript(t, dir, "noop-editor.sh", `:`)

	got, err := OpenWith(Editor{Name: script}, "")
	if err != nil {
		t.Fatalf("OpenWith: %v", err)
	}
	if got != "" {
		t.Fatalf("content = %q, want empty", got)
	}
}

func TestOpenWithEmptyName(t *testing.T) {
	_, err := OpenWith(Editor{}, "x")
	if err == nil {
		t.Fatal("expected an error for an empty editor name")
	}
}

func TestReadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "description.md")
	content := "# Summary\n\nA vulnerability.\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	t.Run("happy path", func(t *testing.T) {
		got, err := ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		if got != content {
			t.Fatalf("content = %q, want %q", got, content)
		}
	})

	t.Run("trims surrounding spaces in path", func(t *testing.T) {
		got, err := ReadFile("  " + path + "  ")
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		if got != content {
			t.Fatalf("content = %q, want %q", got, content)
		}
	})

	t.Run("empty path", func(t *testing.T) {
		if _, err := ReadFile("   "); err == nil {
			t.Fatal("expected an error for an empty path")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := ReadFile(filepath.Join(dir, "nope.md"))
		if err == nil {
			t.Fatal("expected an error for a missing file")
		}
		if !strings.Contains(err.Error(), "does not exist") {
			t.Fatalf("error %q should say the file does not exist", err)
		}
	})

	t.Run("directory", func(t *testing.T) {
		_, err := ReadFile(dir)
		if err == nil {
			t.Fatal("expected an error for a directory")
		}
		if !strings.Contains(err.Error(), "directory") {
			t.Fatalf("error %q should mention directory", err)
		}
	})

	t.Run("home expansion", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		if err := os.WriteFile(filepath.Join(home, "file.md"), []byte("from home\n"), 0o600); err != nil {
			t.Fatalf("write home file: %v", err)
		}
		got, err := ReadFile("~/file.md")
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		if got != "from home\n" {
			t.Fatalf("content = %q, want %q", got, "from home\n")
		}
	})

	t.Run("non regular file", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("no /dev/null equivalent")
		}
		_, err := ReadFile("/dev/null")
		if err == nil {
			t.Fatal("expected an error for a device file")
		}
		if !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("error %q should explain the file type", err)
		}
	})

	t.Run("oversize rejected", func(t *testing.T) {
		big := filepath.Join(dir, "big.md")
		f, err := os.Create(big)
		if err != nil {
			t.Fatalf("create big file: %v", err)
		}
		// Sparse 5 MiB file: allocate no real data.
		if err := f.Truncate(5 << 20); err != nil {
			_ = f.Close()
			t.Fatalf("truncate: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("close big file: %v", err)
		}
		_, err = ReadFile(big)
		if err == nil {
			t.Fatal("expected an error for an oversize file")
		}
		if !strings.Contains(err.Error(), "too large") {
			t.Fatalf("error %q should mention the size limit", err)
		}
	})
}

func TestReadMultiline(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"blank line terminator", "line1\nline2\n\nline3\n", "line1\nline2"},
		{"dot terminator", "line1\nline2\n.\nline3\n", "line1\nline2"},
		{"immediate blank line", "\nanything\n", ""},
		{"eof without terminator", "line1\nline2\n", "line1\nline2"},
		{"eof only", "", ""},
		{"single line", "only\n", "only"},
		{"trims blank padding lines around terminator", "  \nbody\n \n", ""},
		{"preserves internal blank-ish content", "a\nb\nc\n", "a\nb\nc"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out strings.Builder
			got, err := ReadMultiline(strings.NewReader(tc.input), &out, "Description> ")
			if err != nil {
				t.Fatalf("ReadMultiline: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			if !strings.Contains(out.String(), "Description> ") {
				t.Fatalf("prompt %q was not written", out.String())
			}
		})
	}
}

func TestReadMultilineNilWriter(t *testing.T) {
	got, err := ReadMultiline(strings.NewReader("hello\n\n"), nil, "prompt> ")
	if err != nil {
		t.Fatalf("ReadMultiline: %v", err)
	}
	if got != "hello" {
		t.Fatalf("got %q, want hello", got)
	}
}

func TestReadMultilineNilReader(t *testing.T) {
	if _, err := ReadMultiline(nil, nil, "p> "); err == nil {
		t.Fatal("expected an error for a nil reader")
	}
}

// failingWriter always fails; the prompt write must not abort input.
type failingWriter struct{}

func (failingWriter) Write(p []byte) (int, error) { return 0, os.ErrClosed }

func TestReadMultilineWriteErrorIsNotFatal(t *testing.T) {
	got, err := ReadMultiline(strings.NewReader("still works\n\n"), failingWriter{}, "p> ")
	if err != nil {
		t.Fatalf("ReadMultiline: %v", err)
	}
	if got != "still works" {
		t.Fatalf("got %q, want %q", got, "still works")
	}
}

func TestReadMultilineLongLine(t *testing.T) {
	long := strings.Repeat("x", 200<<10)
	got, err := ReadMultiline(strings.NewReader(long+"\n\n"), nil, "")
	if err != nil {
		t.Fatalf("ReadMultiline: %v", err)
	}
	if got != long {
		t.Fatalf("long line was truncated: got %d bytes, want %d", len(got), len(long))
	}
}
