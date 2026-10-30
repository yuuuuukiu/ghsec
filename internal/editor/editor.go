// Package editor resolves the user's preferred terminal editor, shuttles
// vulnerability descriptions through temporary files, and reads descriptions
// from disk or from an interactive multi-line prompt.
//
// Only the standard library is used so the CLI stays dependency-light and the
// behaviour is identical on macOS, Linux and Windows.
package editor

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Editor describes the external editor command used to compose a description.
type Editor struct {
	Name   string   // executable to run
	Args   []string // extra args before the file path (e.g. vim's "-n")
	Source string   // where it came from: "$VISUAL", "$EDITOR", "default"
}

const (
	// maxFileBytes caps how large a user supplied description file may be.
	// It is also used as the maximum length of a single interactive line.
	maxFileBytes = 4 << 20 // 4 MiB

	tempPrefix = "ghsec-description-"
	tempSuffix = ".md"
)

// ResolveEditor picks the editor to use: $VISUAL first, then $EDITOR, then a
// platform default (nano, falling back to vim/vi on Unix; notepad on Windows).
//
// The returned Editor never has an empty Name: if no editor can be found on
// PATH the preferred name is still returned so Open can report something
// actionable.
func ResolveEditor() Editor {
	for _, candidate := range []struct {
		env    string
		source string
	}{
		{"VISUAL", "$VISUAL"},
		{"EDITOR", "$EDITOR"},
	} {
		if ed := parseCommand(os.Getenv(candidate.env), candidate.source); ed.Name != "" {
			return ed
		}
	}
	return defaultEditor()
}

// parseCommand splits an $EDITOR-style value into an executable and its flags.
// The first whitespace-separated token is treated as the executable, so a path
// containing spaces is only supported on a best-effort basis (a "~" prefix is
// expanded for convenience).
func parseCommand(value, source string) Editor {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return Editor{}
	}
	// Best effort for paths containing spaces: if the whole value names an
	// existing executable, use it verbatim rather than splitting it apart.
	if strings.ContainsAny(trimmed, " \t") && isExecutable(trimmed) {
		name, _ := expandTilde(trimmed)
		return Editor{Name: name, Source: source}
	}

	fields := strings.Fields(trimmed)
	name, _ := expandTilde(fields[0])
	return Editor{Name: name, Args: fields[1:], Source: source}
}

// isExecutable reports whether path points at a runnable file.
func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return info.Mode().Perm()&0o111 != 0
}

// expandTilde expands a leading "~" best effort, leaving the value untouched
// when the home directory cannot be determined.
func expandTilde(path string) (string, error) {
	if !strings.HasPrefix(path, "~") {
		return path, nil
	}
	expanded, err := expandHome(path)
	if err != nil {
		return path, err
	}
	return expanded, nil
}

// defaultEditor chooses an editor that exists on this machine.
func defaultEditor() Editor {
	if runtime.GOOS == "windows" {
		return Editor{Name: "notepad", Source: "default"}
	}
	for _, name := range []string{"nano", "vim", "vi"} {
		if _, err := exec.LookPath(name); err == nil {
			return Editor{Name: name, Source: "default"}
		}
	}
	// Nothing was found. Return the preferred name anyway so the error raised by
	// Open tells the user what to install or configure.
	return Editor{Name: "nano", Source: "default"}
}

// Open edits initial in the resolved editor and returns the edited content.
func Open(initial string) (string, error) {
	return OpenWith(ResolveEditor(), initial)
}

// OpenWith is Open with an injectable editor command. It is the test seam.
//
// The initial content is written to a temporary 0600 ".md" file, the editor is
// launched with the terminal's stdin/stdout/stderr attached and the process is
// waited for. The temporary file is always removed.
//
// If the editor exits with a non-zero status (or cannot be started) the content
// of the file is still returned alongside the error, so the user never loses
// what they typed. The returned error is always human readable.
func OpenWith(ed Editor, initial string) (string, error) {
	name := strings.TrimSpace(ed.Name)
	if name == "" {
		return initial, errors.New("no editor configured: set $VISUAL or $EDITOR to the editor you want to use")
	}
	if _, err := exec.LookPath(name); err != nil {
		return initial, fmt.Errorf("editor %q could not be found: install it or point $VISUAL/$EDITOR at an editor on your PATH", name)
	}

	f, err := os.CreateTemp("", tempPrefix+"*"+tempSuffix)
	if err != nil {
		return initial, fmt.Errorf("could not create a temporary description file: %w", err)
	}
	path := f.Name()
	// Always clean up, including when the editor crashes or the read-back fails.
	defer func() { _ = os.Remove(path) }()

	// os.CreateTemp already uses 0600, but be explicit: descriptions may contain
	// unpublished vulnerability details.
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return initial, fmt.Errorf("could not secure the temporary description file: %w", err)
	}
	if initial != "" {
		if _, err := io.WriteString(f, initial); err != nil {
			_ = f.Close()
			return initial, fmt.Errorf("could not write the temporary description file: %w", err)
		}
	}
	if err := f.Close(); err != nil {
		return initial, fmt.Errorf("could not finish writing the temporary description file: %w", err)
	}

	args := make([]string, 0, len(ed.Args)+1)
	args = append(args, ed.Args...)
	args = append(args, path)

	// The editor is chosen by the user (or by this package); running it with the
	// temp file as an argument is the entire point of this function.
	cmd := exec.Command(name, args...) //nolint:gosec // user-selected editor, intentional
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	runErr := cmd.Run()

	content, readErr := os.ReadFile(path)
	if readErr != nil {
		return initial, fmt.Errorf("could not read the edited description back: %w", readErr)
	}
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			return string(content), fmt.Errorf("editor %q exited with status %d; your edits were kept", name, exitErr.ExitCode())
		}
		return string(content), fmt.Errorf("could not start editor %q: %w", name, runErr)
	}
	return string(content), nil
}

// ReadFile reads a user-supplied description path. A leading "~" is expanded,
// directories and files larger than 4 MiB are rejected with friendly errors.
func ReadFile(path string) (string, error) {
	requested := strings.TrimSpace(path)
	if requested == "" {
		return "", errors.New("no file path provided: pass the path to a Markdown or text file")
	}

	expanded, err := expandHome(requested)
	if err != nil {
		return "", err
	}

	info, err := os.Stat(expanded)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("file %q does not exist", requested)
		}
		return "", fmt.Errorf("could not open %q: %w", requested, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("%q is a directory, not a file: pass the path to a Markdown or text file", requested)
	}
	if !info.Mode().IsRegular() {
		// Devices, sockets and pipes can block forever or stream without end; a
		// description must come from a real file.
		return "", fmt.Errorf("%q is not a regular file: pass the path to a Markdown or text file", requested)
	}
	if info.Size() > maxFileBytes {
		return "", fmt.Errorf("file %q is too large (%s): the limit is %s",
			requested, formatBytes(info.Size()), formatBytes(maxFileBytes))
	}

	f, err := os.Open(expanded)
	if err != nil {
		return "", fmt.Errorf("could not open %q: %w", requested, err)
	}
	defer func() { _ = f.Close() }()

	// Re-check the size while reading: Stat can be stale (or report zero for
	// virtual files), and we must never buffer an unbounded amount of data.
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return "", fmt.Errorf("could not read %q: %w", requested, err)
	}
	if len(data) > maxFileBytes {
		return "", fmt.Errorf("file %q is larger than the %s limit: pass a smaller description file",
			requested, formatBytes(maxFileBytes))
	}
	return string(data), nil
}

// expandHome replaces a leading "~" with the current user's home directory.
func expandHome(path string) (string, error) {
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return "", fmt.Errorf("could not locate your home directory to expand %q", path)
	}
	if path == "~" {
		return home, nil
	}
	return filepath.Join(home, path[2:]), nil
}

// formatBytes renders a byte count for human eyes (e.g. "5.0 MiB").
func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	value := float64(n)
	for _, suffix := range []string{"KiB", "MiB", "GiB"} {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f %s", value, suffix)
		}
	}
	return fmt.Sprintf("%.1f TiB", value/unit)
}

// ReadMultiline reads a multi-line description from in, echoing prompt to out
// when out is not nil. Input ends at the first blank line or a line containing
// only ".". End of input (EOF) also ends the read and returns what was
// collected. Lines are joined with "\n" and no trailing newline is added.
//
// An error is returned only when reading from in fails (EOF is not an error) or
// when in is nil. Writing the prompt is best effort: a closed output stream must
// not interrupt typing.
func ReadMultiline(in io.Reader, out io.Writer, prompt string) (string, error) {
	if in == nil {
		return "", errors.New("no input stream to read the description from")
	}
	if out != nil && prompt != "" {
		// Best effort: never abort the user's input because of a write error.
		_, _ = io.WriteString(out, prompt)
	}

	scanner := bufio.NewScanner(in)
	// Allow long lines (up to the file-size cap) instead of failing with
	// bufio.ErrTooLong on a pasted paragraph.
	scanner.Buffer(make([]byte, 0, 64*1024), maxFileBytes)

	lines := make([]string, 0, 8)
	for scanner.Scan() {
		line := scanner.Text()
		switch strings.TrimSpace(line) {
		case "", ".":
			return strings.TrimRight(strings.Join(lines, "\n"), "\n"), nil
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("could not read the description: %w", err)
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n"), nil
}
