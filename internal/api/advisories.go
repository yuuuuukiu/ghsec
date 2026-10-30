package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// advisoryPayload is the wire representation shared by both advisory
// endpoints. Severity is transmitted as a plain lowercase string because the
// public request structs hide the field with `json:"-"`.
type advisoryPayload struct {
	Summary     string `json:"summary"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	CVEID       string `json:"cve_id,omitempty"`
}

// SubmitPrivateReport opens a private vulnerability report on a repository via
// POST /repos/{owner}/{repo}/security-advisories/reports.
//
// The report is only visible to the maintainers and to the reporter.
func (c *Client) SubmitPrivateReport(ctx context.Context, owner, repo string, req PrivateReportRequest) (*Advisory, error) {
	ownerName, repoName, err := normalizeRepoPair(owner, repo)
	if err != nil {
		return nil, err
	}

	summary := strings.TrimSpace(req.Summary)
	description := strings.TrimSpace(req.Description)
	if err := validateSummary(summary); err != nil {
		return nil, err
	}
	if description == "" {
		return nil, fmt.Errorf("the description must not be empty: add details about the vulnerability")
	}
	if err := validateSeverity(req.Severity); err != nil {
		return nil, err
	}

	payload := advisoryPayload{
		Summary:     summary,
		Description: description,
		Severity:    string(req.Severity),
		CVEID:       strings.TrimSpace(req.CVEID),
	}
	return c.postAdvisory(ctx, repoAPIPath(ownerName, repoName)+"/security-advisories/reports", payload)
}

// CreateAdvisoryDraft creates a draft repository security advisory via
// POST /repos/{owner}/{repo}/security-advisories.
//
// GitHub's advisory API accepts a single description field, so req.AffectedText
// is folded into that description as a readable "## Affected versions" section.
func (c *Client) CreateAdvisoryDraft(ctx context.Context, owner, repo string, req AdvisoryDraftRequest) (*Advisory, error) {
	ownerName, repoName, err := normalizeRepoPair(owner, repo)
	if err != nil {
		return nil, err
	}

	summary := strings.TrimSpace(req.Summary)
	description := strings.TrimSpace(req.Description)
	affected := strings.TrimSpace(req.AffectedText)
	if err := validateSummary(summary); err != nil {
		return nil, err
	}
	if description == "" && affected == "" {
		return nil, fmt.Errorf("the description must not be empty: add details about the vulnerability or the affected versions")
	}
	if err := validateSeverity(req.Severity); err != nil {
		return nil, err
	}

	payload := advisoryPayload{
		Summary:     summary,
		Description: composeDraftDescription(description, affected),
		Severity:    string(req.Severity),
		CVEID:       strings.TrimSpace(req.CVEID),
	}
	return c.postAdvisory(ctx, repoAPIPath(ownerName, repoName)+"/security-advisories", payload)
}

// postAdvisory issues the POST and decodes the created advisory. GitHub always
// returns the advisory body on success; an empty (or null) 2xx body is treated
// as an error so callers never receive a half-initialised pointer.
func (c *Client) postAdvisory(ctx context.Context, path string, payload any) (*Advisory, error) {
	var raw json.RawMessage
	if err := c.do(ctx, http.MethodPost, path, payload, &raw); err != nil {
		return nil, err
	}

	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, &APIError{
			StatusCode: http.StatusCreated,
			Message:    "GitHub accepted the request but returned no advisory details",
			Method:     http.MethodPost,
			Path:       path,
		}
	}

	var advisory Advisory
	if err := json.Unmarshal(trimmed, &advisory); err != nil {
		return nil, &APIError{
			StatusCode: http.StatusCreated,
			Message:    "GitHub returned an unexpected response format",
			Method:     http.MethodPost,
			Path:       path,
			Body:       snippet(trimmed),
		}
	}
	if advisory == (Advisory{}) {
		return nil, &APIError{
			StatusCode: http.StatusCreated,
			Message:    "GitHub returned an empty advisory object",
			Method:     http.MethodPost,
			Path:       path,
		}
	}
	return &advisory, nil
}

// composeDraftDescription folds the affected-version text into the advisory
// description as a Markdown section.
func composeDraftDescription(description, affected string) string {
	if affected == "" {
		return description
	}
	section := "## Affected versions\n\n" + affected
	if description == "" {
		return section
	}
	return description + "\n\n" + section
}

// validateSummary rejects empty (or whitespace-only) advisory summaries.
func validateSummary(summary string) error {
	if summary == "" {
		return fmt.Errorf("the summary must not be empty: describe the vulnerability in one line")
	}
	return nil
}

// validateSeverity rejects severities outside GitHub's four levels.
func validateSeverity(sev Severity) error {
	if !sev.Valid() {
		return fmt.Errorf("invalid severity %q: must be one of critical, high, medium, low", string(sev))
	}
	return nil
}
