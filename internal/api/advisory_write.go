package api

// This file implements the write side of the repository advisory API: editing
// an advisory and requesting a CVE id for it.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// validateStateForUpdate normalises patch.State and rejects states PATCH cannot
// set. GitHub accepts draft, published and closed only; triage is assigned by
// GitHub itself when a report is filed and is never settable by a client.
func validateStateForUpdate(state *AdvisoryState) (*AdvisoryState, error) {
	if state == nil {
		return nil, nil
	}
	parsed, err := ParseAdvisoryState(string(*state))
	if err != nil {
		return nil, err
	}
	if !parsed.Editable() {
		return nil, fmt.Errorf("state %q cannot be set: GitHub assigns the triage state when a private report is filed; use draft, published or closed", string(parsed))
	}
	return &parsed, nil
}

// UpdateAdvisory edits a repository advisory via
// PATCH /repos/{owner}/{repo}/security-advisories/{ghsa_id}.
//
// Only the fields present in patch are sent, so clearing a field explicitly
// (for example a CVE id set to "") works while omitted fields stay untouched.
// GitHub answers with the updated advisory, which is returned decoded.
func (c *Client) UpdateAdvisory(ctx context.Context, owner, repo, ghsaID string, patch AdvisoryUpdatePatch) (*AdvisoryDetail, error) {
	ownerName, repoName, err := normalizeRepoPair(owner, repo)
	if err != nil {
		return nil, err
	}
	ghsa, err := normalizeGHSAID(ghsaID)
	if err != nil {
		return nil, err
	}
	if patch.IsEmpty() {
		return nil, fmt.Errorf("nothing to update: set at least one field of the advisory")
	}

	wire := patch
	if wire.State, err = validateStateForUpdate(patch.State); err != nil {
		return nil, err
	}
	if patch.Severity != nil {
		severity, err := ParseSeverity(string(*patch.Severity))
		if err != nil {
			return nil, err
		}
		wire.Severity = &severity
	}
	if patch.CVEID != nil {
		if err := ValidateCVEID(*patch.CVEID); err != nil {
			return nil, err
		}
		cveID := strings.TrimSpace(*patch.CVEID)
		wire.CVEID = &cveID
	}

	path := ghsaAPIPath(ownerName, repoName, ghsa)
	var raw json.RawMessage
	if err := c.do(ctx, http.MethodPatch, path, wire.toWire(), &raw); err != nil {
		return nil, err
	}
	return decodeAdvisoryDetail(raw, http.StatusOK, http.MethodPatch, path)
}

// RequestCVE asks GitHub to issue a CVE id for a repository advisory via
// POST /repos/{owner}/{repo}/security-advisories/{ghsa_id}/cve.
//
// The request carries no body and GitHub answers 202 Accepted because the CVE
// is issued asynchronously: the advisory keeps an empty cve_id until the CVE is
// actually assigned, so a nil error only means "the request was accepted".
func (c *Client) RequestCVE(ctx context.Context, owner, repo, ghsaID string) error {
	ownerName, repoName, err := normalizeRepoPair(owner, repo)
	if err != nil {
		return err
	}
	ghsa, err := normalizeGHSAID(ghsaID)
	if err != nil {
		return err
	}

	path := ghsaAPIPath(ownerName, repoName, ghsa) + "/cve"
	// A nil out means the (usually empty) response body is ignored; every 2xx,
	// including the documented 202, is reported as success by do.
	return c.do(ctx, http.MethodPost, path, nil, nil)
}

// ghsaIDLengths describes the shape of a GHSA identifier:
// "GHSA-" followed by three groups of four characters.
const (
	ghsaPrefix      = "GHSA-"
	ghsaGroupCount  = 3
	ghsaGroupLength = 4
)

// ValidateGHSAID checks that id looks like a GitHub advisory identifier,
// "GHSA-xxxx-xxxx-xxxx". Matching is case-insensitive because GitHub treats the
// id case-insensitively when it is used in a URL path.
func ValidateGHSAID(id string) error {
	_, err := normalizeGHSAID(id)
	return err
}

// normalizeGHSAID validates a GHSA id and returns it in the canonical upper
// case form used by GitHub's API paths.
func normalizeGHSAID(id string) (string, error) {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" {
		return "", fmt.Errorf("the advisory id must not be empty: expected the form GHSA-xxxx-xxxx-xxxx")
	}
	if len(trimmed) != len(ghsaPrefix)+ghsaGroupCount*ghsaGroupLength+ghsaGroupCount-1 {
		return "", invalidGHSAIDError(trimmed, "it must be 19 characters long")
	}
	if !strings.EqualFold(trimmed[:len(ghsaPrefix)], ghsaPrefix) {
		return "", invalidGHSAIDError(trimmed, "it must start with "+ghsaPrefix)
	}

	groups := strings.Split(trimmed[len(ghsaPrefix):], "-")
	if len(groups) != ghsaGroupCount {
		return "", invalidGHSAIDError(trimmed, "it must have three groups of four characters separated by '-'")
	}
	for _, group := range groups {
		if len(group) != ghsaGroupLength {
			return "", invalidGHSAIDError(trimmed, "each group must be exactly four characters")
		}
		for _, r := range group {
			if !isGHSAChar(r) {
				return "", invalidGHSAIDError(trimmed, fmt.Sprintf("%q is not allowed; use letters and digits only", r))
			}
		}
	}
	// GitHub's canonical form is an upper-case "GHSA-" prefix followed by a
	// lower-case suffix (GHSA-qr28-fpjm-wq7f). The API resolves ids
	// case-insensitively, but normalising to the canonical casing keeps URLs,
	// logs and the local history consistent with what GitHub reports back.
	return ghsaPrefix + strings.ToLower(trimmed[len(ghsaPrefix):]), nil
}

// invalidGHSAIDError builds the friendly error shared by the GHSA checks.
func invalidGHSAIDError(id, detail string) error {
	return fmt.Errorf("invalid advisory id %q: %s; expected the form GHSA-xxxx-xxxx-xxxx", id, detail)
}

// isGHSAChar reports whether r may appear in a GHSA id group.
func isGHSAChar(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	default:
		return false
	}
}

// ValidateCVEID checks an optional CVE identifier: the empty string (meaning
// "no CVE") is accepted, anything else must match CVE-YYYY-NNNN with at least
// four digits in the sequence number.
func ValidateCVEID(id string) error {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" {
		return nil
	}

	parts := strings.Split(trimmed, "-")
	if len(parts) != 3 {
		return invalidCVEIDError(trimmed, "it must have the form CVE-YYYY-NNNN")
	}
	if !strings.EqualFold(parts[0], "CVE") {
		return invalidCVEIDError(trimmed, "it must start with CVE-")
	}
	if len(parts[1]) != 4 || !isDigits(parts[1]) {
		return invalidCVEIDError(trimmed, "the year must be four digits")
	}
	if len(parts[2]) < 4 || !isDigits(parts[2]) {
		return invalidCVEIDError(trimmed, "the sequence number must be at least four digits")
	}
	return nil
}

// invalidCVEIDError builds the friendly error shared by the CVE checks.
func invalidCVEIDError(id, detail string) error {
	return fmt.Errorf("invalid CVE id %q: %s (for example CVE-2024-12345); leave it empty to remove the CVE id", id, detail)
}

// isDigits reports whether s is non-empty and made up of ASCII digits only.
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
