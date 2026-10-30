// Package api contains a small, dependency-free GitHub REST API client focused
// on the security advisory and private vulnerability reporting endpoints.
package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Severity is the GitHub advisory severity level.
type Severity string

// Supported severity levels, strongest first.
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// SeverityLevels lists every valid severity in descending order of impact.
var SeverityLevels = []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}

// Valid reports whether s is one of the four GitHub severity levels.
func (s Severity) Valid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		return true
	default:
		return false
	}
}

// ParseSeverity normalises user input (case-insensitive, trimmed).
func ParseSeverity(s string) (Severity, error) {
	sev := Severity(strings.ToLower(strings.TrimSpace(s)))
	if !sev.Valid() {
		return "", fmt.Errorf("invalid severity %q: must be one of critical, high, medium, low", s)
	}
	return sev, nil
}

// SeverityLabel returns a human-friendly title-cased label.
func SeverityLabel(s Severity) string {
	if !s.Valid() {
		return "Unknown"
	}
	return strings.ToUpper(string(s)[:1]) + string(s)[1:]
}

// User is the authenticated account returned by GET /user.
type User struct {
	Login   string `json:"login"`
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	HTMLURL string `json:"html_url"`
	Type    string `json:"type"`
}

// Advisory is the representation returned by both the private report and the
// repository advisory endpoints. Only commonly used fields are modelled; the
// rest of the payload is ignored.
type Advisory struct {
	GHSAID      string `json:"ghsa_id"`
	CVEID       string `json:"cve_id"`
	Summary     string `json:"summary"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	State       string `json:"state"`
	HTMLURL     string `json:"html_url"`
	APIURL      string `json:"url"`
	PublishedAt string `json:"published_at"`
	CreatedAt   string `json:"created_at"`
	Publishing  *struct {
		PublishedAt *string `json:"published_at"`
	} `json:"publishing,omitempty"`
}

// Identifier returns the best available human identifier for the advisory.
func (a *Advisory) Identifier() string {
	if a == nil {
		return ""
	}
	if a.GHSAID != "" {
		return a.GHSAID
	}
	if a.CVEID != "" {
		return a.CVEID
	}
	return "(unknown id)"
}

// Repository is the subset of GET /repos/{owner}/{repo} we care about.
type Repository struct {
	FullName        string `json:"full_name"`
	HTMLURL         string `json:"html_url"`
	Private         bool   `json:"private"`
	DefaultBranch   string `json:"default_branch"`
	AdvisoryEnabled bool   `json:"-"`
}

// PrivateReportRequest is the payload for POST
// /repos/{owner}/{repo}/security-advisories/reports.
type PrivateReportRequest struct {
	Summary     string   `json:"summary"`
	Description string   `json:"description"`
	Severity    Severity `json:"-"`
	CVEID       string   `json:"cve_id,omitempty"`
}

// AdvisoryDraftRequest is the payload for POST
// /repos/{owner}/{repo}/security-advisories.
type AdvisoryDraftRequest struct {
	Summary      string   `json:"summary"`
	Description  string   `json:"description"`
	Severity     Severity `json:"-"`
	CVEID        string   `json:"cve_id,omitempty"`
	AffectedText string   `json:"-"`
}

// APIError is a structured, user-presentable GitHub API failure.
type APIError struct {
	StatusCode int
	Message    string
	DocURL     string
	Method     string
	Path       string
	Body       string
}

// Error implements error. The message is already human readable.
func (e *APIError) Error() string {
	if e == nil {
		return "<nil>"
	}
	msg := strings.TrimSpace(e.Message)
	if msg == "" {
		msg = http.StatusText(e.StatusCode)
	}
	if msg == "" {
		msg = "request failed"
	}
	if e.StatusCode > 0 {
		return fmt.Sprintf("%s (HTTP %d)", msg, e.StatusCode)
	}
	return msg
}

// IsForbidden reports a 403 response.
func (e *APIError) IsForbidden() bool { return e != nil && e.StatusCode == http.StatusForbidden }

// IsNotFound reports a 404 response.
func (e *APIError) IsNotFound() bool { return e != nil && e.StatusCode == http.StatusNotFound }

// IsUnauthorized reports a 401 response.
func (e *APIError) IsUnauthorized() bool { return e != nil && e.StatusCode == http.StatusUnauthorized }

// IsRateLimited reports a 403/429 that carries rate-limit semantics.
func (e *APIError) IsRateLimited() bool {
	if e == nil {
		return false
	}
	low := strings.ToLower(e.Message + " " + e.Body)
	return (e.StatusCode == http.StatusForbidden || e.StatusCode == http.StatusTooManyRequests) &&
		(strings.Contains(low, "rate limit") || strings.Contains(low, "abuse detection"))
}

// AsAPIError unwraps err into an *APIError when possible.
func AsAPIError(err error) (*APIError, bool) {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr, true
	}
	return nil, false
}

// FriendlyMessage translates any error into an actionable, user-facing line.
// It never returns raw JSON or Go runtime text.
func FriendlyMessage(err error, action string) string {
	if err == nil {
		return ""
	}
	if action == "" {
		action = "complete the request"
	}

	apiErr, ok := AsAPIError(err)
	if !ok {
		return fmt.Sprintf("Could not %s: %v", action, err)
	}

	switch {
	case apiErr.IsUnauthorized():
		return "Could not " + action + ": the token was rejected (HTTP 401). " +
			"Check that the token is valid and not expired, then run the profile manager to update it."
	case apiErr.IsForbidden() && apiErr.IsRateLimited():
		return "Could not " + action + ": GitHub rate limit reached. Wait a few minutes and try again."
	case apiErr.IsForbidden():
		return "Could not " + action + ": permission denied (HTTP 403). " +
			"The repository may not have private vulnerability reporting enabled, " +
			"or your token lacks the required scope (classic: 'repo' or 'public_repo'; " +
			"fine-grained: 'Security events' read/write)."
	case apiErr.IsNotFound():
		return "Could not " + action + ": repository or endpoint not found (HTTP 404). " +
			"Check the owner/repo spelling and that your token can access the repository."
	case apiErr.StatusCode == http.StatusUnprocessableEntity:
		return "Could not " + action + ": GitHub rejected the submitted data (HTTP 422). " +
			"Verify the summary, description, severity and CVE ID are valid."
	case apiErr.StatusCode >= 500:
		return "Could not " + action + ": GitHub is having trouble right now (HTTP " +
			fmt.Sprint(apiErr.StatusCode) + "). Please retry shortly."
	case apiErr.StatusCode > 0:
		return "Could not " + action + ": " + apiErr.Error()
	default:
		return "Could not " + action + ": " + apiErr.Error()
	}
}
