// Package config implements cross-platform configuration discovery, credential
// profile storage and atomic, permission-restricted persistence for ghsec.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

// ErrNoConfig is returned by Load when no configuration file exists yet. It is
// a sentinel: callers should treat it as "first run", not as a failure.
var ErrNoConfig = errors.New("ghsec config not found")

// FileMode is the permission applied to the configuration file. It holds
// personal access tokens, so it must never be group/world readable.
const FileMode os.FileMode = 0o600

// DirMode is the permission applied to the configuration directory.
const DirMode os.FileMode = 0o700

// ConfigFileName is the base name of the on-disk configuration file.
const ConfigFileName = "config.json"

// maxConfigSize bounds how much we are willing to read from disk.
const maxConfigSize = 1 << 20 // 1 MiB

// Profile is a single stored credential entry, keyed by an alias.
type Profile struct {
	Token    string `json:"token"`
	Username string `json:"username"`
}

// Config is the root persisted document.
type Config struct {
	ActiveProfile string             `json:"active_profile"`
	Profiles      map[string]Profile `json:"profiles"`

	// History records advisories and private reports submitted from this
	// machine. GitHub's REST API exposes no "reports I filed" listing (the
	// reports endpoint is POST-only), so this local index is what lets ghsec
	// show the user's own submission history and refresh each entry's live
	// status from the API afterwards.
	History []Submission `json:"history,omitempty"`
}

// SubmissionKind distinguishes the two ways a vulnerability enters GitHub.
type SubmissionKind string

// The two submission kinds.
const (
	// KindReport is a private vulnerability report filed by a researcher.
	KindReport SubmissionKind = "report"
	// KindAdvisory is a maintainer-created advisory draft.
	KindAdvisory SubmissionKind = "advisory"
)

// Submission is one entry in the local history index.
//
// It deliberately stores no vulnerability detail: only the identifiers needed to
// re-query GitHub for the authoritative, current state.
type Submission struct {
	Kind        SubmissionKind `json:"kind"`
	Owner       string         `json:"owner"`
	Repo        string         `json:"repo"`
	GHSAID      string         `json:"ghsa_id,omitempty"`
	CVEID       string         `json:"cve_id,omitempty"`
	Summary     string         `json:"summary"`
	Severity    string         `json:"severity"`
	URL         string         `json:"url,omitempty"`
	Alias       string         `json:"alias,omitempty"`
	SubmittedAt time.Time      `json:"submitted_at"`
}

// RepoSpec returns "owner/repo".
func (s Submission) RepoSpec() string {
	if s.Owner == "" || s.Repo == "" {
		return ""
	}
	return s.Owner + "/" + s.Repo
}

// maxHistoryEntries bounds the local index so the config cannot grow forever.
const maxHistoryEntries = 200

// AddSubmission prepends an entry to the history index, deduplicating on the
// advisory identifier when GitHub returned one, and trims the tail.
func (c *Config) AddSubmission(sub Submission) {
	if c == nil {
		return
	}
	if sub.SubmittedAt.IsZero() {
		sub.SubmittedAt = time.Now().UTC()
	}

	if sub.GHSAID != "" {
		kept := c.History[:0]
		for _, existing := range c.History {
			if existing.GHSAID == sub.GHSAID && existing.RepoSpec() == sub.RepoSpec() {
				continue
			}
			kept = append(kept, existing)
		}
		c.History = kept
	}

	c.History = append([]Submission{sub}, c.History...)
	if len(c.History) > maxHistoryEntries {
		c.History = c.History[:maxHistoryEntries]
	}
}

// Submissions returns the history index, newest first.
func (c *Config) Submissions() []Submission {
	if c == nil {
		return nil
	}
	return c.History
}

// ClearHistory drops every recorded submission.
func (c *Config) ClearHistory() {
	if c == nil {
		return
	}
	c.History = nil
}

// tokenPrefixes are the well-known GitHub token prefixes we surface unmasked so
// users can identify the credential class at a glance.
var tokenPrefixes = []string{"github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_"}

// aliasPattern keeps aliases shell-friendly and map-key-safe.
var aliasPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)

// configHomeEnv allows tests and power users to pin the config root.
const configHomeEnv = "GHSEC_CONFIG_HOME"

// Dir returns the directory holding the ghsec configuration.
//
// Precedence:
//  1. $GHSEC_CONFIG_HOME (explicit override, used by tests)
//  2. $XDG_CONFIG_HOME/ghsec (Unix; XDG spec)
//  3. os.UserConfigDir()/ghsec — %APPDATA%\ghsec on Windows,
//     ~/Library/Application Support/ghsec on macOS, ~/.config/ghsec on Linux
//
// Note that os.UserConfigDir already honours XDG_CONFIG_HOME on Unix, but we
// check it explicitly so the behaviour is documented and stable even if the
// standard library's rules change.
func Dir() (string, error) {
	if custom := strings.TrimSpace(os.Getenv(configHomeEnv)); custom != "" {
		return custom, nil
	}
	if runtime.GOOS != "windows" {
		if xdg := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); xdg != "" {
			return filepath.Join(xdg, "ghsec"), nil
		}
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate user config directory: %w", err)
	}
	return filepath.Join(base, "ghsec"), nil
}

// Path returns the absolute path of the configuration file.
func Path() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, ConfigFileName), nil
}

// Load reads the configuration from the default location.
func Load() (*Config, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}
	return LoadFrom(path)
}

// LoadFrom reads the configuration from an explicit path. It is the test seam
// for Load and also used by callers that manage a custom location.
//
// A missing file yields (emptyConfig, ErrNoConfig). A present but malformed
// file yields a wrapped error so the UI can report it without panicking.
func LoadFrom(path string) (*Config, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return newConfig(), fmt.Errorf("%w at %s", ErrNoConfig, path)
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("config path %s is a directory", path)
	}
	if info.Size() > maxConfigSize {
		return nil, fmt.Errorf("config file %s is unexpectedly large (%d bytes)", path, info.Size())
	}

	raw, err := os.ReadFile(path) //nolint:gosec // path is derived from trusted config dirs
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return newConfig(), fmt.Errorf("%w at %s (empty file)", ErrNoConfig, path)
	}

	cfg := newConfig()
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	cfg.normalize()
	return cfg, nil
}

// newConfig returns an initialised, empty configuration.
func newConfig() *Config {
	return &Config{Profiles: map[string]Profile{}}
}

// normalize repairs partial documents (nil maps, dangling active profile).
func (c *Config) normalize() {
	if c.Profiles == nil {
		c.Profiles = map[string]Profile{}
	}
	if c.ActiveProfile != "" {
		if _, ok := c.Profiles[c.ActiveProfile]; !ok {
			c.ActiveProfile = ""
		}
	}
	if c.ActiveProfile == "" {
		if aliases := c.Aliases(); len(aliases) > 0 {
			c.ActiveProfile = aliases[0]
		}
	}
}

// Save writes the configuration to the default location.
func (c *Config) Save() error {
	path, err := Path()
	if err != nil {
		return err
	}
	return c.SaveTo(path)
}

// SaveTo atomically writes the configuration to path with 0600 permissions.
//
// The write goes to a sibling temporary file that is fsynced and then renamed
// over the target, so an interrupted run can never leave a truncated config.
func (c *Config) SaveTo(path string) error {
	if c == nil {
		return errors.New("save config: nil config")
	}
	c.normalize()

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, DirMode); err != nil {
		return fmt.Errorf("create config directory %s: %w", dir, err)
	}
	// MkdirAll does not tighten permissions of pre-existing directories.
	if err := os.Chmod(dir, DirMode); err != nil && runtime.GOOS != "windows" {
		return fmt.Errorf("secure config directory %s: %w", dir, err)
	}

	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	raw = append(raw, '\n')

	tmp, err := os.CreateTemp(dir, ConfigFileName+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary config file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		// Best effort: remove the temp file if we failed before the rename.
		_ = os.Remove(tmpName)
	}()

	if err := tmp.Chmod(FileMode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("secure temporary config file: %w", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("flush config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close config: %w", err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace config %s: %w", path, err)
	}
	// Rename preserves the temp file mode, but be explicit about the contract.
	if err := os.Chmod(path, FileMode); err != nil && runtime.GOOS != "windows" {
		return fmt.Errorf("secure config file %s: %w", path, err)
	}
	return nil
}

// IsEmpty reports whether no usable credential is stored.
func (c *Config) IsEmpty() bool {
	return c == nil || len(c.Profiles) == 0
}

// Active returns the alias and profile of the currently selected credential.
func (c *Config) Active() (string, Profile, bool) {
	if c == nil || len(c.Profiles) == 0 {
		return "", Profile{}, false
	}
	if c.ActiveProfile != "" {
		if p, ok := c.Profiles[c.ActiveProfile]; ok {
			return c.ActiveProfile, p, true
		}
	}
	aliases := c.Aliases()
	alias := aliases[0]
	return alias, c.Profiles[alias], true
}

// SetActive selects an existing profile as the active one.
func (c *Config) SetActive(alias string) error {
	if c == nil {
		return errors.New("config is nil")
	}
	if _, ok := c.Profiles[alias]; !ok {
		return fmt.Errorf("profile %q does not exist", alias)
	}
	c.ActiveProfile = alias
	return nil
}

// AddProfile stores or replaces a profile and, when no profile is active yet,
// makes it active.
func (c *Config) AddProfile(alias string, p Profile) error {
	if c == nil {
		return errors.New("config is nil")
	}
	if err := ValidateAlias(alias); err != nil {
		return err
	}
	if strings.TrimSpace(p.Token) == "" {
		return errors.New("token must not be empty")
	}
	if c.Profiles == nil {
		c.Profiles = map[string]Profile{}
	}
	c.Profiles[alias] = p
	if c.ActiveProfile == "" {
		c.ActiveProfile = alias
	}
	return nil
}

// RemoveProfile deletes a profile. Removing the final profile would leave the
// tool unusable, so it is rejected; the UI deletes the config file instead.
func (c *Config) RemoveProfile(alias string) error {
	if c == nil {
		return errors.New("config is nil")
	}
	if _, ok := c.Profiles[alias]; !ok {
		return fmt.Errorf("profile %q does not exist", alias)
	}
	if len(c.Profiles) == 1 {
		return errors.New("cannot remove the only profile: add another one first")
	}
	delete(c.Profiles, alias)
	if c.ActiveProfile == alias {
		c.ActiveProfile = ""
		c.normalize()
	}
	return nil
}

// Aliases returns every stored alias in sorted order for stable UI rendering.
func (c *Config) Aliases() []string {
	if c == nil || len(c.Profiles) == 0 {
		return nil
	}
	out := make([]string, 0, len(c.Profiles))
	for alias := range c.Profiles {
		out = append(out, alias)
	}
	sort.Strings(out)
	return out
}

// ValidateAlias enforces the alias grammar used by the TUI and config loader.
func ValidateAlias(alias string) error {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		return errors.New("alias must not be empty")
	}
	if !aliasPattern.MatchString(alias) {
		return errors.New("alias must start with a letter or digit and contain only letters, digits, '.', '_' or '-' (max 32 chars)")
	}
	return nil
}

// MaskToken hides all but the last four characters of a token. Short or empty
// values never leak: they are replaced by a generic placeholder.
func MaskToken(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return "(none)"
	}
	// Keep a recognisable token prefix so "ghp_xxxx1234" becomes
	// "ghp_****1234", which helps users tell which credential is stored.
	prefix := ""
	rest := token
	for _, candidate := range tokenPrefixes {
		if strings.HasPrefix(token, candidate) {
			prefix = candidate
			rest = token[len(candidate):]
			break
		}
	}
	if len(rest) <= 4 {
		// Too short to reveal anything: mask the remainder entirely.
		return prefix + strings.Repeat("*", max(4, len(rest)))
	}
	return prefix + "****" + rest[len(rest)-4:]
}

// max is a tiny local helper so the package builds on all Go versions.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
