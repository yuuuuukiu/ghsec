package main

// This file implements the local submission history: `ghsec history`.
//
// Why this exists: GitHub's REST API is POST-only for private vulnerability
// reports and offers no "advisories I filed" listing, so a client cannot query
// its own submissions from the server. ghsec therefore keeps a small local index
// of what it submitted and refreshes each entry's live status on demand.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/yuuuuukiu/ghsec/internal/api"
	"github.com/yuuuuukiu/ghsec/internal/config"
	"github.com/yuuuuukiu/ghsec/internal/tui"
)

const historyUsage = `ghsec history — show what you have submitted from this machine

Usage:
  ghsec history list [--limit N] [--refresh] [--json]
  ghsec history clear [--yes]

Notes:
  * GitHub has no API to list the private reports you filed, so ghsec records
    each successful submission locally (ghsa id, repo, summary, severity).
  * --refresh re-reads the current state of every recorded advisory from GitHub
    and shows its live status, current CVE id and latest update time.
  * --refresh needs credentials; without it the list is served from disk.
  * "state" reflects GitHub's authority, not a local guess.

Examples:
  ghsec history list
  ghsec history list --refresh
  ghsec history clear --yes
`

// historyRow is the machine-readable shape of one history entry.
type historyRow struct {
	Kind        string `json:"kind"`
	Repository  string `json:"repository"`
	GHSAID      string `json:"ghsa_id,omitempty"`
	CVEID       string `json:"cve_id,omitempty"`
	Summary     string `json:"summary"`
	Severity    string `json:"severity,omitempty"`
	State       string `json:"state,omitempty"`
	URL         string `json:"url,omitempty"`
	SubmittedAt string `json:"submitted_at"`
	Stale       bool   `json:"stale,omitempty"`
	Error       string `json:"error,omitempty"`
}

// runHistoryCmd implements `ghsec history`.
func runHistoryCmd(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usagef("history: a subcommand is required (list, clear)\n\n%s", historyUsage)
	}
	switch args[0] {
	case "list", "ls":
		return historyList(ctx, args[1:])
	case "clear":
		return historyClear(args[1:])
	case "-h", "--help", "help":
		fmt.Print(historyUsage)
		return errFlagHandled
	default:
		return usagef("history: unknown subcommand %q (use list or clear)\n\n%s", args[0], historyUsage)
	}
}

// historyList prints the recorded submissions, optionally refreshing state.
func historyList(ctx context.Context, args []string) error {
	fs := buildFlagSet("history list")
	var limit int
	var refresh, asJSON bool
	var c clientFlags
	fs.IntVar(&limit, "limit", 20, "maximum number of entries to show")
	fs.BoolVar(&refresh, "refresh", false, "re-read the current state of each advisory from GitHub")
	fs.BoolVar(&asJSON, "json", false, "print JSON on stdout")
	c.register(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if limit <= 0 {
		return usagef("--limit must be greater than zero")
	}

	cfg, err := loadConfigOrEmpty()
	if err != nil {
		return err
	}
	entries := cfg.Submissions()
	if len(entries) == 0 {
		if asJSON {
			return json.NewEncoder(os.Stdout).Encode([]historyRow{})
		}
		fmt.Fprintln(os.Stdout, "no submissions recorded yet")
		fmt.Fprintln(os.Stderr, "run `ghsec report` or `ghsec advisory` to file one")
		return nil
	}
	if len(entries) > limit {
		entries = entries[:limit]
	}

	rows := make([]historyRow, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, historyRow{
			Kind:        string(e.Kind),
			Repository:  e.RepoSpec(),
			GHSAID:      e.GHSAID,
			CVEID:       e.CVEID,
			Summary:     e.Summary,
			Severity:    e.Severity,
			URL:         e.URL,
			SubmittedAt: e.SubmittedAt.Format(time.RFC3339),
		})
	}

	if refresh {
		if err := refreshHistory(ctx, rows, c); err != nil {
			return err
		}
	}

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	header := "SUBMITTED\tKIND\tREPO\tGHSA\tCVE\tSEVERITY\tSTATE\tSUMMARY"
	if !refresh {
		header = "SUBMITTED\tKIND\tREPO\tGHSA\tCVE\tSEVERITY\tSUMMARY"
	}
	fmt.Fprintln(w, header)
	for _, r := range rows {
		when := r.SubmittedAt
		if t, err := time.Parse(time.RFC3339, r.SubmittedAt); err == nil {
			when = t.Local().Format("2006-01-02 15:04")
		}
		cve := r.CVEID
		if cve == "" {
			cve = "-"
		}
		fields := []string{when, r.Kind, r.Repository, firstNonEmpty(r.GHSAID, "-"), cve, firstNonEmpty(r.Severity, "-")}
		if refresh {
			state := r.State
			if r.Error != "" {
				state = "!"
			}
			fields = append(fields, firstNonEmpty(state, "-"))
		}
		fields = append(fields, truncateRunes(r.Summary, 60))
		fmt.Fprintln(w, strings.Join(fields, "\t"))
	}
	if err := w.Flush(); err != nil {
		return err
	}

	if refresh {
		for _, r := range rows {
			if r.Error != "" {
				fmt.Fprintf(os.Stderr, "could not refresh %s: %s\n", r.GHSAID, r.Error)
			}
		}
	}
	return nil
}

// refreshHistory replaces each row's local guess with GitHub's current state.
//
// Failures are recorded per row instead of aborting: a single unreadable
// advisory must not hide the rest of the history.
func refreshHistory(ctx context.Context, rows []historyRow, flags clientFlags) error {
	client, _, err := flags.resolve()
	if err != nil {
		// Fall back to a clear message rather than failing the whole listing.
		return fmt.Errorf("--refresh needs credentials: %w", err)
	}

	for i := range rows {
		if rows[i].GHSAID == "" {
			rows[i].Stale = true
			rows[i].Error = "no advisory id was returned at submission time"
			continue
		}
		owner, repo, ok := splitRepo(rows[i].Repository)
		if !ok {
			rows[i].Error = "recorded repository is malformed"
			continue
		}

		callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		detail, gerr := client.GetAdvisory(callCtx, owner, repo, rows[i].GHSAID)
		cancel()

		if gerr != nil {
			rows[i].Error = api.FriendlyMessage(gerr, "read the advisory status")
			// A 404 means the advisory is gone (or never visible to this token).
			if apiErr, ok := api.AsAPIError(gerr); ok && apiErr.IsNotFound() {
				rows[i].State = "unavailable"
			}
			continue
		}
		rows[i].State = detail.AdvisoryStateValue().Label()
		if detail.CVEID != "" {
			rows[i].CVEID = detail.CVEID
		}
		if detail.HTMLURL != "" {
			rows[i].URL = detail.HTMLURL
		}
	}
	return nil
}

// historyClear wipes the local index.
func historyClear(args []string) error {
	fs := buildFlagSet("history clear")
	var yes bool
	fs.BoolVar(&yes, "yes", false, "clear without asking for confirmation")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if !yes {
		ok, err := confirmSubmit(false, "Clear the local submission history?")
		if err != nil {
			if errors.Is(err, tui.ErrAborted) {
				return errCancelled
			}
			return err
		}
		if !ok {
			fmt.Fprintln(os.Stderr, "cancelled: history was kept")
			return errCancelled
		}
	}

	cfg, err := loadConfigOrEmpty()
	if err != nil {
		return err
	}
	cfg.ClearHistory()
	if err := cfg.Save(); err != nil {
		return fmt.Errorf("save configuration: %w", err)
	}
	fmt.Fprintln(os.Stdout, "submission history cleared")
	return nil
}

// splitRepo splits "owner/repo", reporting whether it was well formed.
func splitRepo(spec string) (string, string, bool) {
	owner, repo, err := api.ValidateRepoSpec(spec)
	if err != nil {
		return "", "", false
	}
	return owner, repo, true
}

// ensure config and api stay referenced even if helpers change.
var _ = config.KindReport
