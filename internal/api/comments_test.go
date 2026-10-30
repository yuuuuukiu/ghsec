package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// commentJSON is a realistic advisory comment payload.
const commentJSON = `{
  "id": 42,
  "node_id": "MDI6QWR2aXNvcnlDb21tZW50NDI=",
  "url": "https://api.github.com/repos/octocat/hello-world/security-advisories/GHSA-abcd-1234-efgh/comments/42",
  "html_url": "https://github.com/octocat/hello-world/security/advisories/GHSA-abcd-1234-efgh#advisory-comment-42",
  "body": "Thanks for the report, we are working on a fix.",
  "user": {"login": "octocat", "id": 1, "type": "User"},
  "created_at": "2024-05-01T10:00:00Z",
  "updated_at": "2024-05-01T10:05:00Z",
  "author_association": "OWNER"
}`

// commentListJSON is a two-entry comment list payload.
const commentListJSON = `[
  {"id": 42, "body": "Thanks for the report, we are working on a fix.", "user": {"login": "octocat"}},
  {"id": 43, "body": "A patch is ready for review.", "user": {"login": "helper"}}
]`

func TestListCommentsHappyPath(t *testing.T) {
	client, log := newScriptedClient(t, scriptedResponse{status: http.StatusOK, body: commentListJSON})

	page, err := client.ListComments(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh", AdvisoryListOptions{
		PerPage: 50,
		Page:    2,
	})
	if err != nil {
		t.Fatalf("ListComments returned error: %v", err)
	}

	req := log.last(t)
	if req.method != http.MethodGet {
		t.Errorf("method = %q, want %q", req.method, http.MethodGet)
	}
	if want := "/repos/octocat/hello-world/security-advisories/GHSA-abcd-1234-efgh/comments"; req.path != want {
		t.Errorf("path = %q, want %q", req.path, want)
	}
	assertGitHubRequestHeaders(t, req.header)

	if len(page.Items) != 2 {
		t.Fatalf("len(Items) = %d, want 2", len(page.Items))
	}
	if got, want := page.Items[0].ID, int64(42); got != want {
		t.Errorf("Items[0].ID = %d, want %d", got, want)
	}
	if got, want := page.Items[0].AuthorLogin(), "octocat"; got != want {
		t.Errorf("Items[0].AuthorLogin() = %q, want %q", got, want)
	}
	if got, want := page.Items[1].Body, "A patch is ready for review."; got != want {
		t.Errorf("Items[1].Body = %q, want %q", got, want)
	}
	if got, want := page.TotalCount, -1; got != want {
		t.Errorf("TotalCount = %d, want %d", got, want)
	}
	if page.HasMore || page.NextPage != 0 {
		t.Errorf("NextPage = %d, HasMore = %v; want 0/false without a Link header", page.NextPage, page.HasMore)
	}
}

func TestListCommentsPagination(t *testing.T) {
	link := `<https://api.github.com/repos/octocat/hello-world/security-advisories/GHSA-abcd-1234-efgh/comments?per_page=30&page=2>; rel="next"`
	client, _ := newScriptedClient(t, scriptedResponse{
		status: http.StatusOK,
		body:   commentListJSON,
		header: map[string]string{"Link": link},
	})

	page, err := client.ListComments(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh", AdvisoryListOptions{})
	if err != nil {
		t.Fatalf("ListComments returned error: %v", err)
	}
	if got, want := page.NextPage, 2; got != want {
		t.Errorf("NextPage = %d, want %d", got, want)
	}
	if !page.HasMore {
		t.Error("HasMore = false, want true when GitHub sends a rel=\"next\" link")
	}
}

func TestListCommentsNullBodyIsEmpty(t *testing.T) {
	client, _ := newScriptedClient(t, scriptedResponse{status: http.StatusOK, body: "null"})

	page, err := client.ListComments(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh", AdvisoryListOptions{})
	if err != nil {
		t.Fatalf("ListComments returned error: %v", err)
	}
	if page.Items == nil {
		t.Fatal("Items is nil, want an empty slice so callers can range over it")
	}
	if len(page.Items) != 0 {
		t.Errorf("len(Items) = %d, want 0", len(page.Items))
	}
	if page.TotalCount != -1 || page.HasMore || page.NextPage != 0 {
		t.Errorf("TotalCount = %d, NextPage = %d, HasMore = %v; want -1/0/false",
			page.TotalCount, page.NextPage, page.HasMore)
	}
}

func TestListCommentsRejectsInvalidInputWithoutNetwork(t *testing.T) {
	tests := []struct {
		name  string
		owner string
		repo  string
		ghsa  string
	}{
		{name: "empty ghsa", owner: "octocat", repo: "hello-world", ghsa: ""},
		{name: "malformed ghsa", owner: "octocat", repo: "hello-world", ghsa: "GHSA-abcd-1234"},
		{name: "invalid owner", owner: "octo cat", repo: "hello-world", ghsa: "GHSA-abcd-1234-efgh"},
		{name: "missing repo", owner: "octocat", repo: "", ghsa: "GHSA-abcd-1234-efgh"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, log := hitSensingClient(t)

			page, err := client.ListComments(context.Background(), tc.owner, tc.repo, tc.ghsa, AdvisoryListOptions{})
			if err == nil {
				t.Fatalf("expected a validation error, got %#v", page)
			}
			if page.Items != nil {
				t.Errorf("Items = %#v, want nil on error", page.Items)
			}
			if _, ok := AsAPIError(err); ok {
				t.Fatalf("validation error must not be an *APIError: %v", err)
			}
			if got := log.count(); got != 0 {
				t.Errorf("server received %d requests, want 0", got)
			}
		})
	}
}

func TestListCommentsAPIError(t *testing.T) {
	client, _ := newScriptedClient(t, scriptedResponse{
		status: http.StatusNotFound,
		body:   `{"message":"Not Found"}`,
	})

	page, err := client.ListComments(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh", AdvisoryListOptions{})
	if err == nil {
		t.Fatalf("expected an error, got %#v", page)
	}
	apiErr, ok := AsAPIError(err)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if !apiErr.IsNotFound() {
		t.Errorf("IsNotFound() = false, want true (status %d)", apiErr.StatusCode)
	}
}

func TestCreateCommentHappyPath(t *testing.T) {
	client, log := newScriptedClient(t, scriptedResponse{status: http.StatusCreated, body: commentJSON})

	comment, err := client.CreateComment(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh", "Thanks for the report, we are working on a fix.")
	if err != nil {
		t.Fatalf("CreateComment returned error: %v", err)
	}
	if comment == nil {
		t.Fatal("CreateComment returned a nil comment")
	}

	req := log.last(t)
	if req.method != http.MethodPost {
		t.Errorf("method = %q, want %q", req.method, http.MethodPost)
	}
	if want := "/repos/octocat/hello-world/security-advisories/GHSA-abcd-1234-efgh/comments"; req.path != want {
		t.Errorf("path = %q, want %q", req.path, want)
	}
	assertGitHubRequestHeaders(t, req.header)
	assertJSONContentType(t, req.header)

	body := decodeBody(t, req.body)
	if got, want := body["body"], "Thanks for the report, we are working on a fix."; got != want {
		t.Errorf(`body["body"] = %#v, want %q`, got, want)
	}
	if len(body) != 1 {
		t.Errorf("body has %d keys, want exactly 1 (the comment body): %s", len(body), string(req.body))
	}

	if got, want := comment.ID, int64(42); got != want {
		t.Errorf("ID = %d, want %d", got, want)
	}
	if got, want := comment.Body, "Thanks for the report, we are working on a fix."; got != want {
		t.Errorf("Body = %q, want %q", got, want)
	}
	if got, want := comment.AuthorLogin(), "octocat"; got != want {
		t.Errorf("AuthorLogin() = %q, want %q", got, want)
	}
	if got, want := comment.AuthorAssociation, "OWNER"; got != want {
		t.Errorf("AuthorAssociation = %q, want %q", got, want)
	}
	if got, want := comment.HTMLURL, "https://github.com/octocat/hello-world/security/advisories/GHSA-abcd-1234-efgh#advisory-comment-42"; got != want {
		t.Errorf("HTMLURL = %q, want %q", got, want)
	}
}

func TestCreateCommentTrimsBody(t *testing.T) {
	client, log := newScriptedClient(t, scriptedResponse{status: http.StatusCreated, body: commentJSON})

	if _, err := client.CreateComment(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh", "  \n  LGTM  \n\n"); err != nil {
		t.Fatalf("CreateComment returned error: %v", err)
	}

	body := decodeBody(t, log.last(t).body)
	if got, want := body["body"], "LGTM"; got != want {
		t.Errorf(`body["body"] = %#v, want %q (trimmed)`, got, want)
	}
}

func TestCreateCommentRejectsEmptyBodyWithoutNetwork(t *testing.T) {
	bodies := []struct {
		name string
		body string
	}{
		{name: "empty", body: ""},
		{name: "spaces", body: "    "},
		{name: "newlines", body: "\n\t\n"},
	}

	for _, tc := range bodies {
		t.Run(tc.name, func(t *testing.T) {
			client, log := hitSensingClient(t)

			comment, err := client.CreateComment(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh", tc.body)
			if err == nil {
				t.Fatalf("expected a validation error, got %#v", comment)
			}
			if comment != nil {
				t.Errorf("comment = %#v, want nil", comment)
			}
			if _, ok := AsAPIError(err); ok {
				t.Fatalf("validation error must not be an *APIError: %v", err)
			}
			if got := log.count(); got != 0 {
				t.Errorf("server received %d requests, want 0", got)
			}
		})
	}
}

func TestCommentBodyLengthLimit(t *testing.T) {
	limit := maxCommentBodyLen

	t.Run("at the limit is accepted", func(t *testing.T) {
		client, log := newScriptedClient(t, scriptedResponse{status: http.StatusCreated, body: commentJSON})

		if _, err := client.CreateComment(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh", strings.Repeat("a", limit)); err != nil {
			t.Fatalf("CreateComment returned error at the length limit: %v", err)
		}
		body := decodeBody(t, log.last(t).body)
		if got, want := len(body["body"].(string)), limit; got != want {
			t.Errorf("len(body) = %d, want %d", got, want)
		}
	})

	t.Run("over the limit is rejected", func(t *testing.T) {
		client, log := hitSensingClient(t)

		if _, err := client.CreateComment(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh", strings.Repeat("a", limit+1)); err == nil {
			t.Fatal("expected a length validation error, got nil")
		}
		if got := log.count(); got != 0 {
			t.Errorf("server received %d requests, want 0", got)
		}
	})
}

func TestGetCommentHappyPath(t *testing.T) {
	client, log := newScriptedClient(t, scriptedResponse{status: http.StatusOK, body: commentJSON})

	comment, err := client.GetComment(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh", 42)
	if err != nil {
		t.Fatalf("GetComment returned error: %v", err)
	}
	if comment == nil {
		t.Fatal("GetComment returned a nil comment")
	}

	req := log.last(t)
	if req.method != http.MethodGet {
		t.Errorf("method = %q, want %q", req.method, http.MethodGet)
	}
	if want := "/repos/octocat/hello-world/security-advisories/GHSA-abcd-1234-efgh/comments/42"; req.path != want {
		t.Errorf("path = %q, want %q", req.path, want)
	}
	if got, want := comment.ID, int64(42); got != want {
		t.Errorf("ID = %d, want %d", got, want)
	}
	if len(req.body) != 0 {
		t.Errorf("GET carried a body: %q", string(req.body))
	}
}

func TestGetCommentNotFound(t *testing.T) {
	client, _ := newScriptedClient(t, scriptedResponse{
		status: http.StatusNotFound,
		body:   `{"message":"Not Found"}`,
	})

	comment, err := client.GetComment(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh", 42)
	if err == nil {
		t.Fatalf("expected an error, got %#v", comment)
	}
	if comment != nil {
		t.Errorf("comment = %#v, want nil", comment)
	}
	apiErr, ok := AsAPIError(err)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if !apiErr.IsNotFound() {
		t.Errorf("IsNotFound() = false, want true (status %d)", apiErr.StatusCode)
	}
}

func TestUpdateCommentHappyPath(t *testing.T) {
	client, log := newScriptedClient(t, scriptedResponse{status: http.StatusOK, body: commentJSON})

	comment, err := client.UpdateComment(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh", 42, "Updated: fixed in 1.2.3.")
	if err != nil {
		t.Fatalf("UpdateComment returned error: %v", err)
	}
	if comment == nil {
		t.Fatal("UpdateComment returned a nil comment")
	}

	req := log.last(t)
	if req.method != http.MethodPatch {
		t.Errorf("method = %q, want %q", req.method, http.MethodPatch)
	}
	if want := "/repos/octocat/hello-world/security-advisories/GHSA-abcd-1234-efgh/comments/42"; req.path != want {
		t.Errorf("path = %q, want %q", req.path, want)
	}
	assertGitHubRequestHeaders(t, req.header)
	assertJSONContentType(t, req.header)

	body := decodeBody(t, req.body)
	if got, want := body["body"], "Updated: fixed in 1.2.3."; got != want {
		t.Errorf(`body["body"] = %#v, want %q`, got, want)
	}
	if len(body) != 1 {
		t.Errorf("body has %d keys, want exactly 1: %s", len(body), string(req.body))
	}
	if got, want := comment.ID, int64(42); got != want {
		t.Errorf("ID = %d, want %d", got, want)
	}
}

func TestUpdateCommentRejectsInvalidInputWithoutNetwork(t *testing.T) {
	tests := []struct {
		name      string
		owner     string
		repo      string
		ghsa      string
		commentID int64
		body      string
	}{
		{name: "zero comment id", owner: "octocat", repo: "hello-world", ghsa: "GHSA-abcd-1234-efgh", commentID: 0, body: "hi"},
		{name: "negative comment id", owner: "octocat", repo: "hello-world", ghsa: "GHSA-abcd-1234-efgh", commentID: -7, body: "hi"},
		{name: "empty body", owner: "octocat", repo: "hello-world", ghsa: "GHSA-abcd-1234-efgh", commentID: 42, body: "  "},
		{name: "malformed ghsa", owner: "octocat", repo: "hello-world", ghsa: "GHSA-abcd", commentID: 42, body: "hi"},
		{name: "invalid repo", owner: "octocat", repo: "hello world", ghsa: "GHSA-abcd-1234-efgh", commentID: 42, body: "hi"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, log := hitSensingClient(t)

			comment, err := client.UpdateComment(context.Background(), tc.owner, tc.repo, tc.ghsa, tc.commentID, tc.body)
			if err == nil {
				t.Fatalf("expected a validation error, got %#v", comment)
			}
			if comment != nil {
				t.Errorf("comment = %#v, want nil", comment)
			}
			if _, ok := AsAPIError(err); ok {
				t.Fatalf("validation error must not be an *APIError: %v", err)
			}
			if got := log.count(); got != 0 {
				t.Errorf("server received %d requests, want 0", got)
			}
		})
	}
}

func TestCommentIDValidationWithoutNetwork(t *testing.T) {
	for _, id := range []int64{0, -1, -42} {
		client, log := hitSensingClient(t)

		comment, err := client.GetComment(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh", id)
		if err == nil {
			t.Fatalf("GetComment(id=%d) returned no error, got %#v", id, comment)
		}
		if got := log.count(); got != 0 {
			t.Errorf("id %d: server received %d requests, want 0", id, got)
		}
	}
}

func TestCommentEmptyResponseIsError(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "empty body", body: ""},
		{name: "json null", body: "null"},
		{name: "empty object", body: "{}"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := newScriptedClient(t, scriptedResponse{status: http.StatusCreated, body: tc.body})

			comment, err := client.CreateComment(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh", "a reply")
			if err == nil {
				t.Fatalf("expected an error for a %q body, got %#v", tc.body, comment)
			}
			if comment != nil {
				t.Errorf("comment = %#v, want nil", comment)
			}
			if _, ok := AsAPIError(err); !ok {
				t.Fatalf("expected *APIError, got %T: %v", err, err)
			}
		})
	}
}

func TestCommentMalformedResponseIsError(t *testing.T) {
	client, _ := newScriptedClient(t, scriptedResponse{status: http.StatusOK, body: `{"id":"not-a-number"}`})

	comment, err := client.GetComment(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh", 42)
	if err == nil {
		t.Fatalf("expected an error, got %#v", comment)
	}
	apiErr, ok := AsAPIError(err)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.Body == "" {
		t.Error("APIError.Body is empty, want a snippet of the offending payload")
	}
}

func TestCommentPathEscapesCommentID(t *testing.T) {
	client, log := newScriptedClient(t, scriptedResponse{status: http.StatusOK, body: commentJSON})

	const id int64 = 1234567890
	if _, err := client.GetComment(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh", id); err != nil {
		t.Fatalf("GetComment returned error: %v", err)
	}
	want := "/repos/octocat/hello-world/security-advisories/GHSA-abcd-1234-efgh/comments/" + strconv.FormatInt(id, 10)
	if got := log.last(t).path; got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
}

func TestCommentJSONRoundTrip(t *testing.T) {
	var comment Comment
	if err := json.Unmarshal([]byte(commentJSON), &comment); err != nil {
		t.Fatalf("unmarshal comment: %v", err)
	}
	if got, want := comment.ID, int64(42); got != want {
		t.Errorf("ID = %d, want %d", got, want)
	}
	if got, want := comment.User.LoginOrUnknown(), "octocat"; got != want {
		t.Errorf("User.LoginOrUnknown() = %q, want %q", got, want)
	}

	encoded, err := json.Marshal(comment)
	if err != nil {
		t.Fatalf("marshal comment: %v", err)
	}
	if !strings.Contains(string(encoded), `"id":42`) {
		t.Errorf("re-encoded comment lost its id: %s", string(encoded))
	}
}
