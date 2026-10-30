package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const repositoryJSON = `{
  "full_name": "octocat/hello-world",
  "html_url": "https://github.com/octocat/hello-world",
  "private": true,
  "default_branch": "main"
}`

func TestGetRepositoryHappyPath(t *testing.T) {
	client, rec := newTestClient(t, http.StatusOK, repositoryJSON)

	repo, err := client.GetRepository(context.Background(), "octocat", "hello-world")
	if err != nil {
		t.Fatalf("GetRepository returned error: %v", err)
	}
	if repo == nil {
		t.Fatal("GetRepository returned a nil repository")
	}
	if got, want := repo.FullName, "octocat/hello-world"; got != want {
		t.Errorf("FullName = %q, want %q", got, want)
	}
	if got, want := repo.HTMLURL, "https://github.com/octocat/hello-world"; got != want {
		t.Errorf("HTMLURL = %q, want %q", got, want)
	}
	if !repo.Private {
		t.Error("Private = false, want true")
	}
	if got, want := repo.DefaultBranch, "main"; got != want {
		t.Errorf("DefaultBranch = %q, want %q", got, want)
	}
	// The shared test helper answers every request with repositoryJSON, which has
	// no "enabled" field, so the reporting hint must degrade to false rather than
	// failing the lookup.
	if repo.AdvisoryEnabled {
		t.Error("AdvisoryEnabled = true, want false when the reporting endpoint returns no enabled flag")
	}

	// The shared helper records only the most recent request, which is the
	// best-effort advisory hint issued after the repository lookup. Both calls
	// must be GETs carrying the mandatory GitHub headers.
	if got, want := rec.method, http.MethodGet; got != want {
		t.Errorf("method = %q, want %q", got, want)
	}
	if got, want := rec.path, "/repos/octocat/hello-world/private-vulnerability-reporting"; got != want {
		t.Errorf("last path = %q, want %q", got, want)
	}
	assertGitHubRequestHeaders(t, rec.header)
	if len(rec.body) != 0 {
		t.Errorf("GET request carried a body: %q", rec.bodyString)
	}
}

// newRepoTestClient serves the repository object and the dedicated
// private-vulnerability-reporting endpoint from one mock server.
func newRepoTestClient(t *testing.T, reportingStatus int, reportingBody string) (*Client, *[]string) {
	t.Helper()
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/octocat/hello-world/private-vulnerability-reporting":
			w.WriteHeader(reportingStatus)
			if reportingBody != "" {
				_, _ = io.WriteString(w, reportingBody)
			}
		case "/repos/octocat/hello-world":
			_, _ = io.WriteString(w, repositoryJSON)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"message":"Not Found"}`)
		}
	}))
	t.Cleanup(srv.Close)
	return NewClientWithBaseURL(testToken, srv.URL), &paths
}

func TestGetRepositoryAdvisoryReportingEnabled(t *testing.T) {
	client, paths := newRepoTestClient(t, http.StatusOK, `{"enabled":true}`)

	repo, err := client.GetRepository(context.Background(), "octocat", "hello-world")
	if err != nil {
		t.Fatalf("GetRepository returned error: %v", err)
	}
	if !repo.AdvisoryEnabled {
		t.Error("AdvisoryEnabled = false, want true for {\"enabled\":true}")
	}
	want := []string{
		"/repos/octocat/hello-world",
		"/repos/octocat/hello-world/private-vulnerability-reporting",
	}
	if len(*paths) != len(want) {
		t.Fatalf("request paths = %v, want %v", *paths, want)
	}
	for i := range want {
		if (*paths)[i] != want[i] {
			t.Fatalf("request paths = %v, want %v", *paths, want)
		}
	}
}

func TestGetRepositoryAdvisoryReportingDisabled(t *testing.T) {
	client, _ := newRepoTestClient(t, http.StatusOK, `{"enabled":false}`)

	repo, err := client.GetRepository(context.Background(), "octocat", "hello-world")
	if err != nil {
		t.Fatalf("GetRepository returned error: %v", err)
	}
	if repo.AdvisoryEnabled {
		t.Error("AdvisoryEnabled = true, want false for {\"enabled\":false}")
	}
}

func TestGetRepositoryAdvisoryHintIsBestEffort(t *testing.T) {
	// The hint must never break the lookup: forbidden, missing, or broken
	// responses all collapse to "not enabled".
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{"forbidden for this token", http.StatusForbidden, `{"message":"Resource not accessible"}`},
		{"endpoint missing on GHES", http.StatusNotFound, `{"message":"Not Found"}`},
		{"unexpected body", http.StatusOK, `not json`},
		{"empty body", http.StatusOK, ``},
		{"server error", http.StatusInternalServerError, `{"message":"boom"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := newRepoTestClient(t, tc.status, tc.body)
			repo, err := client.GetRepository(context.Background(), "octocat", "hello-world")
			if err != nil {
				t.Fatalf("GetRepository must tolerate a failing hint, got error: %v", err)
			}
			if repo == nil {
				t.Fatal("GetRepository returned a nil repository")
			}
			if repo.AdvisoryEnabled {
				t.Error("AdvisoryEnabled = true, want false when the hint cannot be determined")
			}
			if repo.FullName != "octocat/hello-world" {
				t.Errorf("FullName = %q, want the repository data to survive", repo.FullName)
			}
		})
	}
}

func TestGetRepositoryAPIErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		check  func(t *testing.T, apiErr *APIError)
	}{
		{
			name:   "403 forbidden",
			status: http.StatusForbidden,
			body:   `{"message":"Resource not accessible by personal access token"}`,
			check: func(t *testing.T, apiErr *APIError) {
				t.Helper()
				if !apiErr.IsForbidden() {
					t.Errorf("IsForbidden() = false, want true")
				}
			},
		},
		{
			name:   "404 not found",
			status: http.StatusNotFound,
			body:   `{"message":"Not Found"}`,
			check: func(t *testing.T, apiErr *APIError) {
				t.Helper()
				if !apiErr.IsNotFound() {
					t.Errorf("IsNotFound() = false, want true")
				}
			},
		},
		{
			name:   "401 unauthorized",
			status: http.StatusUnauthorized,
			body:   `{"message":"Bad credentials"}`,
			check: func(t *testing.T, apiErr *APIError) {
				t.Helper()
				if !apiErr.IsUnauthorized() {
					t.Errorf("IsUnauthorized() = false, want true")
				}
			},
		},
		{
			name:   "422 unprocessable",
			status: http.StatusUnprocessableEntity,
			body:   `{"message":"Validation Failed"}`,
			check: func(t *testing.T, apiErr *APIError) {
				t.Helper()
				if apiErr.StatusCode != http.StatusUnprocessableEntity {
					t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, http.StatusUnprocessableEntity)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := newTestClient(t, tc.status, tc.body)
			repo, err := client.GetRepository(context.Background(), "octocat", "hello-world")
			if err == nil {
				t.Fatalf("expected an error, got repository %#v", repo)
			}
			if repo != nil {
				t.Errorf("repository = %#v, want nil on error", repo)
			}
			apiErr, ok := AsAPIError(err)
			if !ok {
				t.Fatalf("expected *APIError, got %T: %v", err, err)
			}
			tc.check(t, apiErr)
		})
	}
}

func TestInvalidRepoSkippedByNetworkForced(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(repositoryJSON))
	}))
	t.Cleanup(srv.Close)
	client := NewClientWithBaseURL(testToken, srv.URL)

	invalid := []struct {
		owner string
		repo  string
	}{
		{"", "hello-world"},
		{"octocat", ""},
		{"a b", "hello-world"},
		{"owner", "re po"},
		{"octocat/repo", "hello-world"},
		{"..", "hello-world"},
		{"octocat", ".."},
		{"octo<cat", "hello-world"},
	}

	for _, tc := range invalid {
		repo, err := client.GetRepository(context.Background(), tc.owner, tc.repo)
		if err == nil {
			t.Errorf("GetRepository(%q, %q) = %#v, want an error", tc.owner, tc.repo, repo)
		}
		if repo != nil {
			t.Errorf("GetRepository(%q, %q) returned a non-nil repository on error", tc.owner, tc.repo)
		}
		if _, ok := AsAPIError(err); ok {
			t.Errorf("GetRepository(%q, %q) returned an *APIError for invalid local input: %v", tc.owner, tc.repo, err)
		}
	}

	if hit {
		t.Error("invalid repository specs must not trigger an HTTP request, but the test server was hit")
	}
}

func TestValidateRepoSpec(t *testing.T) {
	tests := []struct {
		name      string
		spec      string
		wantOwner string
		wantRepo  string
		wantErr   bool
	}{
		{name: "mixed case", spec: "octocat/Hello-World", wantOwner: "octocat", wantRepo: "Hello-World"},
		{name: "single chars", spec: "a/b", wantOwner: "a", wantRepo: "b"},
		{name: "dots and dashes", spec: "my-org.name/my_repo.v2", wantOwner: "my-org.name", wantRepo: "my_repo.v2"},
		{name: "leading and trailing punctuation", spec: "-.-/-repo.", wantOwner: "-.-", wantRepo: "-repo."},
		{name: "surrounding spaces trimmed", spec: "  octocat/hello-world  ", wantOwner: "octocat", wantRepo: "hello-world"},
		{name: "max owner length", spec: strings.Repeat("a", 39) + "/b", wantOwner: strings.Repeat("a", 39), wantRepo: "b"},
		{name: "max repo length", spec: "a/" + strings.Repeat("b", 100), wantOwner: "a", wantRepo: strings.Repeat("b", 100)},

		{name: "empty", spec: "", wantErr: true},
		{name: "whitespace only", spec: "   ", wantErr: true},
		{name: "no slash", spec: "noslash", wantErr: true},
		{name: "two slashes", spec: "a/b/c", wantErr: true},
		{name: "empty owner", spec: "/repo", wantErr: true},
		{name: "empty repo", spec: "owner/", wantErr: true},
		{name: "space before slash", spec: "owner /repo", wantErr: true},
		{name: "space in repo", spec: "owner/re po", wantErr: true},
		{name: "double dot in repo", spec: "owner/re..po", wantErr: true},
		{name: "owner too long", spec: strings.Repeat("a", 40) + "/b", wantErr: true},
		{name: "repo too long", spec: "a/" + strings.Repeat("b", 101), wantErr: true},
		{name: "angle bracket", spec: "owner/re<po", wantErr: true},
		{name: "quote", spec: `owner/re"po`, wantErr: true},
		{name: "at sign", spec: "own@er/repo", wantErr: true},
		{name: "tab", spec: "owner\trepo", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			owner, repo, err := ValidateRepoSpec(tc.spec)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ValidateRepoSpec(%q) = (%q, %q, nil), want an error", tc.spec, owner, repo)
				}
				if owner != "" || repo != "" {
					t.Errorf("ValidateRepoSpec(%q) returned parts (%q, %q) alongside an error", tc.spec, owner, repo)
				}
				if !strings.Contains(err.Error(), "invalid repository") {
					t.Errorf("error %q should mention %q for readability", err, "invalid repository")
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateRepoSpec(%q) returned unexpected error: %v", tc.spec, err)
			}
			if owner != tc.wantOwner || repo != tc.wantRepo {
				t.Errorf("ValidateRepoSpec(%q) = (%q, %q), want (%q, %q)", tc.spec, owner, repo, tc.wantOwner, tc.wantRepo)
			}
		})
	}
}

func TestValidateRepoSpecErrorsAreNotAPIErrors(t *testing.T) {
	_, _, err := ValidateRepoSpec("not-a-spec")
	if err == nil {
		t.Fatal("expected an error")
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		t.Fatalf("ValidateRepoSpec returned an *APIError: %v", err)
	}
}

// TestRepoAPIPathEscapesSegments guards the url.PathEscape call directly: a test
// server sees the decoded path, so escaping must be asserted on the builder.
func TestRepoAPIPathEscapesSegments(t *testing.T) {
	tests := []struct {
		owner string
		repo  string
		want  string
	}{
		{owner: "octocat", repo: "hello-world", want: "/repos/octocat/hello-world"},
		{owner: "a b", repo: "c/d", want: "/repos/a%20b/c%2Fd"},
		{owner: "..", repo: "x?y", want: "/repos/../x%3Fy"},
	}

	for _, tc := range tests {
		if got := repoAPIPath(tc.owner, tc.repo); got != tc.want {
			t.Errorf("repoAPIPath(%q, %q) = %q, want %q", tc.owner, tc.repo, got, tc.want)
		}
	}
}
