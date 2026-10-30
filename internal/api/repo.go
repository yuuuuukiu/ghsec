package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// GitHub's documented length limits for repository identifiers.
const (
	maxOwnerNameLen = 39
	maxRepoNameLen  = 100
)

// GetRepository fetches the repository metadata used to pre-flight an advisory
// submission.
//
// Private vulnerability reporting is *not* part of the repository object, so it
// is queried through its own endpoint (GET .../private-vulnerability-reporting)
// and folded into AdvisoryEnabled. That supporting call is best effort: the
// setting is only used for an advisory hint, so a non-2xx response, a missing
// permission or an older GHES installation must not fail the whole lookup.
func (c *Client) GetRepository(ctx context.Context, owner, repo string) (*Repository, error) {
	ownerName, repoName, err := normalizeRepoPair(owner, repo)
	if err != nil {
		return nil, err
	}

	var wire Repository
	if err := c.do(ctx, http.MethodGet, repoAPIPath(ownerName, repoName), nil, &wire); err != nil {
		return nil, err
	}

	wire.AdvisoryEnabled = c.privateVulnerabilityReportingEnabled(ctx, ownerName, repoName)
	return &wire, nil
}

// privateVulnerabilityReportingEnabled reports whether the repository accepts
// private vulnerability reports, per the dedicated endpoint that returns
// {"enabled": true|false}.
//
// Any failure is treated as "unknown"/false: this is an optional hint, never a
// gate, so it must not turn a working submission into an error.
func (c *Client) privateVulnerabilityReportingEnabled(ctx context.Context, owner, repo string) bool {
	var payload struct {
		Enabled bool `json:"enabled"`
	}
	path := repoAPIPath(owner, repo) + "/private-vulnerability-reporting"
	if err := c.do(ctx, http.MethodGet, path, nil, &payload); err != nil {
		return false
	}
	return payload.Enabled
}

// repoAPIPath builds "/repos/{owner}/{repo}" with both segments escaped.
func repoAPIPath(owner, repo string) string {
	return "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo)
}

// normalizeRepoPair trims and validates an owner/repo pair supplied by a caller,
// returning the cleaned halves that are safe to place in a URL path.
func normalizeRepoPair(owner, repo string) (string, string, error) {
	ownerName := strings.TrimSpace(owner)
	repoName := strings.TrimSpace(repo)
	if ownerName == "" || repoName == "" {
		return "", "", fmt.Errorf("invalid repository %q: expected the form owner/repo", ownerName+"/"+repoName)
	}
	return ValidateRepoSpec(ownerName + "/" + repoName)
}

// ValidateRepoSpec splits and validates an "owner/repo" specification.
//
// Whitespace around the spec is ignored. Each half must be non-empty, at most
// 39 (owner) or 100 (repository) characters long, free of "..", and made up of
// GitHub's allowed characters [A-Za-z0-9._-] only.
func ValidateRepoSpec(spec string) (owner, repo string, err error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return "", "", fmt.Errorf("invalid repository %q: must not be empty; expected the form owner/repo", spec)
	}
	if strings.Count(trimmed, "/") != 1 {
		return "", "", fmt.Errorf("invalid repository %q: expected exactly one '/' as in owner/repo", spec)
	}

	ownerName, repoName, _ := strings.Cut(trimmed, "/")
	if err := validateRepoPart("owner", ownerName, maxOwnerNameLen); err != nil {
		return "", "", fmt.Errorf("invalid repository %q: %w", spec, err)
	}
	if err := validateRepoPart("repository name", repoName, maxRepoNameLen); err != nil {
		return "", "", fmt.Errorf("invalid repository %q: %w", spec, err)
	}
	return ownerName, repoName, nil
}

// validateRepoPart checks one half of an owner/repo specification.
func validateRepoPart(kind, part string, maxLen int) error {
	if part == "" {
		return fmt.Errorf("the %s is empty", kind)
	}
	if len(part) > maxLen {
		return fmt.Errorf("the %s %q is %d characters long, GitHub allows at most %d", kind, part, len(part), maxLen)
	}
	if strings.Contains(part, "..") {
		return fmt.Errorf("the %s %q must not contain %q", kind, part, "..")
	}
	for _, r := range part {
		if !isRepoPartRune(r) {
			return fmt.Errorf("the %s %q contains %q, which is not allowed; use only letters, digits, '.', '_' and '-'", kind, part, r)
		}
	}
	return nil
}

// isRepoPartRune reports whether r belongs to GitHub's safe repository charset.
func isRepoPartRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	case r == '.', r == '_', r == '-':
		return true
	default:
		return false
	}
}
