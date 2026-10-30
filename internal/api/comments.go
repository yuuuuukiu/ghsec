package api

// This file implements the comment thread attached to a repository advisory.
// Comments are how a maintainer replies to the reporter and how collaborators
// discuss a private report, so the four endpoints below form the collaboration
// path of the tool.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// maxCommentBodyLen bounds a single comment. GitHub rejects longer bodies, so
// the limit is enforced locally to fail fast with an actionable message.
const maxCommentBodyLen = 65536

// ListComments returns one page of advisory comments via
// GET /repos/{owner}/{repo}/security-advisories/{ghsa_id}/comments.
//
// The endpoint returns a bare JSON array. Paging information is taken from the
// Link header when GitHub sends one; a response without that header is a
// perfectly normal single page, so NextPage stays 0 and HasMore stays false.
// TotalCount is -1 because the API exposes no total.
func (c *Client) ListComments(ctx context.Context, owner, repo, ghsaID string, opts AdvisoryListOptions) (ListPage[Comment], error) {
	page := ListPage[Comment]{TotalCount: -1}

	ownerName, repoName, err := normalizeRepoPair(owner, repo)
	if err != nil {
		return page, err
	}
	ghsa, err := normalizeGHSAID(ghsaID)
	if err != nil {
		return page, err
	}

	// Paging is applied opportunistically: GitHub tolerates the standard paging
	// parameters on array endpoints even where the description omits them.
	path := commentsAPIPath(ownerName, repoName, ghsa) + "?" + pagingQueryValues(opts).Encode()
	header, err := c.doWithHeader(ctx, http.MethodGet, path, nil, &page.Items)
	if err != nil {
		return page, err
	}
	if page.Items == nil {
		page.Items = []Comment{}
	}
	page.NextPage = nextPageFromHeader(header)
	page.HasMore = page.NextPage > 0
	return page, nil
}

// CreateComment posts a comment on an advisory thread via
// POST /repos/{owner}/{repo}/security-advisories/{ghsa_id}/comments.
//
// This is the supported way to reply to the reporter of a private report.
func (c *Client) CreateComment(ctx context.Context, owner, repo, ghsaID, body string) (*Comment, error) {
	ownerName, repoName, err := normalizeRepoPair(owner, repo)
	if err != nil {
		return nil, err
	}
	ghsa, err := normalizeGHSAID(ghsaID)
	if err != nil {
		return nil, err
	}
	commentBody, err := normalizeCommentBody(body)
	if err != nil {
		return nil, err
	}

	path := commentsAPIPath(ownerName, repoName, ghsa)
	payload := commentPayload{Body: commentBody}
	var raw json.RawMessage
	if err := c.do(ctx, http.MethodPost, path, payload, &raw); err != nil {
		return nil, err
	}
	return decodeComment(raw, http.StatusCreated, http.MethodPost, path)
}

// GetComment fetches a single advisory comment via
// GET /repos/{owner}/{repo}/security-advisories/{ghsa_id}/comments/{comment_id}.
func (c *Client) GetComment(ctx context.Context, owner, repo, ghsaID string, commentID int64) (*Comment, error) {
	ownerName, repoName, err := normalizeRepoPair(owner, repo)
	if err != nil {
		return nil, err
	}
	ghsa, err := normalizeGHSAID(ghsaID)
	if err != nil {
		return nil, err
	}
	if err := validateCommentID(commentID); err != nil {
		return nil, err
	}

	path := commentAPIPath(ownerName, repoName, ghsa, commentID)
	var raw json.RawMessage
	if err := c.do(ctx, http.MethodGet, path, nil, &raw); err != nil {
		return nil, err
	}
	return decodeComment(raw, http.StatusOK, http.MethodGet, path)
}

// UpdateComment replaces the body of an existing advisory comment via
// PATCH /repos/{owner}/{repo}/security-advisories/{ghsa_id}/comments/{comment_id}.
func (c *Client) UpdateComment(ctx context.Context, owner, repo, ghsaID string, commentID int64, body string) (*Comment, error) {
	ownerName, repoName, err := normalizeRepoPair(owner, repo)
	if err != nil {
		return nil, err
	}
	ghsa, err := normalizeGHSAID(ghsaID)
	if err != nil {
		return nil, err
	}
	if err := validateCommentID(commentID); err != nil {
		return nil, err
	}
	commentBody, err := normalizeCommentBody(body)
	if err != nil {
		return nil, err
	}

	path := commentAPIPath(ownerName, repoName, ghsa, commentID)
	payload := commentPayload{Body: commentBody}
	var raw json.RawMessage
	if err := c.do(ctx, http.MethodPatch, path, payload, &raw); err != nil {
		return nil, err
	}
	return decodeComment(raw, http.StatusOK, http.MethodPatch, path)
}

// commentPayload is the wire shape shared by the create and update endpoints.
type commentPayload struct {
	Body string `json:"body"`
}

// commentsAPIPath builds the comment collection path of one advisory.
func commentsAPIPath(owner, repo, ghsaID string) string {
	return ghsaAPIPath(owner, repo, ghsaID) + "/comments"
}

// commentAPIPath builds the path of one comment below an advisory.
func commentAPIPath(owner, repo, ghsaID string, commentID int64) string {
	return commentsAPIPath(owner, repo, ghsaID) + "/" + url.PathEscape(strconv.FormatInt(commentID, 10))
}

// normalizeCommentBody trims a comment body and validates its length. The
// trimmed body is what gets sent, so a whitespace-only comment is rejected
// instead of silently posting an empty reply.
func normalizeCommentBody(body string) (string, error) {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return "", fmt.Errorf("the comment must not be empty: write a reply before sending it")
	}
	if count := utf8.RuneCountInString(trimmed); count > maxCommentBodyLen {
		return "", fmt.Errorf("the comment is %d characters long, GitHub allows at most %d", count, maxCommentBodyLen)
	}
	return trimmed, nil
}

// validateCommentID rejects comment identifiers that cannot exist.
func validateCommentID(commentID int64) error {
	if commentID <= 0 {
		return fmt.Errorf("invalid comment id %d: it must be a positive number", commentID)
	}
	return nil
}

// decodeComment turns a raw 2xx body into a Comment. A body-less or null
// response becomes an error rather than a zero-valued comment.
func decodeComment(raw json.RawMessage, status int, method, path string) (*Comment, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, &APIError{
			StatusCode: status,
			Message:    "GitHub returned no comment details",
			Method:     method,
			Path:       path,
		}
	}

	var comment Comment
	if err := json.Unmarshal(trimmed, &comment); err != nil {
		return nil, &APIError{
			StatusCode: status,
			Message:    "GitHub returned an unexpected response format",
			Method:     method,
			Path:       path,
			Body:       snippet(trimmed),
		}
	}
	if comment.ID == 0 && strings.TrimSpace(comment.Body) == "" {
		return nil, &APIError{
			StatusCode: status,
			Message:    "GitHub returned an empty comment object",
			Method:     method,
			Path:       path,
		}
	}
	return &comment, nil
}
