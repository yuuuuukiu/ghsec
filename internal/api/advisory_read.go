package api

// This file implements the read side of the repository advisory API: listing
// advisories page by page and fetching a single advisory in full detail.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Pagination defaults and limits documented for the advisory list endpoint.
const (
	defaultAdvisoryPerPage = 30
	maxAdvisoryPerPage     = 100
)

// advisorySortValues lists the accepted values of the advisory list `sort`
// parameter.
var advisorySortValues = []string{"created", "updated", "published"}

// ListAdvisories returns one page of repository security advisories via
// GET /repos/{owner}/{repo}/security-advisories.
//
// GitHub answers with a bare JSON array and reports paging through the Link
// header, so the returned envelope carries NextPage/HasMore derived from that
// header. The API exposes no total count, hence TotalCount is always -1.
// Items is never nil: an empty (or null) response yields an empty slice.
func (c *Client) ListAdvisories(ctx context.Context, owner, repo string, opts AdvisoryListOptions) (ListPage[AdvisoryDetail], error) {
	page := ListPage[AdvisoryDetail]{TotalCount: -1}

	ownerName, repoName, err := normalizeRepoPair(owner, repo)
	if err != nil {
		return page, err
	}
	query, err := advisoryListQuery(opts)
	if err != nil {
		return page, err
	}

	path := repoAPIPath(ownerName, repoName) + "/security-advisories?" + query.Encode()
	header, err := c.doWithHeader(ctx, http.MethodGet, path, nil, &page.Items)
	if err != nil {
		return page, err
	}
	if page.Items == nil {
		page.Items = []AdvisoryDetail{}
	}
	page.NextPage = nextPageFromHeader(header)
	page.HasMore = page.NextPage > 0
	return page, nil
}

// GetAdvisory fetches a single repository advisory via
// GET /repos/{owner}/{repo}/security-advisories/{ghsa_id}.
func (c *Client) GetAdvisory(ctx context.Context, owner, repo, ghsaID string) (*AdvisoryDetail, error) {
	ownerName, repoName, err := normalizeRepoPair(owner, repo)
	if err != nil {
		return nil, err
	}
	ghsa, err := normalizeGHSAID(ghsaID)
	if err != nil {
		return nil, err
	}

	path := ghsaAPIPath(ownerName, repoName, ghsa)
	var raw json.RawMessage
	if err := c.do(ctx, http.MethodGet, path, nil, &raw); err != nil {
		return nil, err
	}
	return decodeAdvisoryDetail(raw, http.StatusOK, http.MethodGet, path)
}

// advisoryListQuery validates the advisory-specific filters and returns the
// query values for GET .../security-advisories.
//
// Validation happens here, before any request is built, so a typo in a filter
// can never reach GitHub.
func advisoryListQuery(opts AdvisoryListOptions) (url.Values, error) {
	query := pagingQueryValues(opts)

	if state := strings.ToLower(strings.TrimSpace(string(opts.State))); state != "" {
		if !AdvisoryState(state).Valid() {
			return nil, fmt.Errorf("invalid state %q: must be one of draft, triage, published, closed", opts.State)
		}
		query.Set("state", state)
	}
	if sortBy := strings.ToLower(strings.TrimSpace(opts.Sort)); sortBy != "" {
		if !isOneOf(advisorySortValues, sortBy) {
			return nil, fmt.Errorf("invalid sort %q: must be one of created, updated, published", opts.Sort)
		}
		query.Set("sort", sortBy)
	}
	if direction := strings.ToLower(strings.TrimSpace(opts.Direction)); direction != "" {
		if direction != "asc" && direction != "desc" {
			return nil, fmt.Errorf("invalid direction %q: must be asc or desc", opts.Direction)
		}
		query.Set("direction", direction)
	}
	return query, nil
}

// pagingQueryValues normalises the paging half of opts and renders it as query
// values. GitHub clamps per_page to 1..100 and page to 1, so the same clamping
// is applied locally to keep requests predictable.
func pagingQueryValues(opts AdvisoryListOptions) url.Values {
	perPage := opts.PerPage
	switch {
	case perPage <= 0:
		perPage = defaultAdvisoryPerPage
	case perPage > maxAdvisoryPerPage:
		perPage = maxAdvisoryPerPage
	}
	page := opts.Page
	if page < 1 {
		page = 1
	}

	query := url.Values{}
	query.Set("per_page", strconv.Itoa(perPage))
	query.Set("page", strconv.Itoa(page))
	return query
}

// ghsaAPIPath builds the path of one advisory below a repository. owner and
// repo are expected to be validated, and ghsaID is already normalised, so the
// segments are escaped defensively only.
func ghsaAPIPath(owner, repo, ghsaID string) string {
	return repoAPIPath(owner, repo) + "/security-advisories/" + url.PathEscape(ghsaID)
}

// decodeAdvisoryDetail turns a raw 2xx body into an AdvisoryDetail. Empty or
// null payloads become a clear error instead of a zero-valued advisory, so
// callers never render a blank detail view for a request that "succeeded".
func decodeAdvisoryDetail(raw json.RawMessage, status int, method, path string) (*AdvisoryDetail, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, &APIError{
			StatusCode: status,
			Message:    "GitHub returned no advisory details",
			Method:     method,
			Path:       path,
		}
	}

	var detail AdvisoryDetail
	if err := json.Unmarshal(trimmed, &detail); err != nil {
		return nil, &APIError{
			StatusCode: status,
			Message:    "GitHub returned an unexpected response format",
			Method:     method,
			Path:       path,
			Body:       snippet(trimmed),
		}
	}
	return &detail, nil
}

// isOneOf reports whether value is present in allowed.
func isOneOf(allowed []string, value string) bool {
	for _, candidate := range allowed {
		if candidate == value {
			return true
		}
	}
	return false
}
