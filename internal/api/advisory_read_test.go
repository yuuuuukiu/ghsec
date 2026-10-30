package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// scriptedResponse is one canned HTTP reply served by newScriptedClient.
type scriptedResponse struct {
	status int
	body   string
	header map[string]string
}

// scriptedRequest is a snapshot of one request a scripted server received.
type scriptedRequest struct {
	method   string
	path     string
	rawQuery string
	query    url.Values
	header   http.Header
	body     []byte
}

// requestLog collects the requests served by a scripted server.
type requestLog struct {
	mu   sync.Mutex
	reqs []scriptedRequest
}

// record appends one observed request.
func (l *requestLog) record(req scriptedRequest) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reqs = append(l.reqs, req)
}

// count reports how many requests the server saw.
func (l *requestLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.reqs)
}

// last returns the most recent request, failing the test when there is none.
func (l *requestLog) last(t *testing.T) scriptedRequest {
	t.Helper()

	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.reqs) == 0 {
		t.Fatal("the test server received no request")
	}
	return l.reqs[len(l.reqs)-1]
}

// newScriptedClient starts a test server that serves the given responses in
// order and records every request it receives. Extra calls beyond the script
// are recorded and answered with a 500 so accidental requests are obvious.
func newScriptedClient(t *testing.T, responses ...scriptedResponse) (*Client, *requestLog) {
	t.Helper()

	log := &requestLog{}
	var mu sync.Mutex
	calls := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		log.record(scriptedRequest{
			method:   r.Method,
			path:     r.URL.Path,
			rawQuery: r.URL.RawQuery,
			query:    r.URL.Query(),
			header:   r.Header.Clone(),
			body:     raw,
		})

		mu.Lock()
		index := calls
		calls++
		mu.Unlock()

		if index >= len(responses) {
			t.Errorf("unexpected request #%d: %s %s", index+1, r.Method, r.URL.String())
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"message":"unexpected request"}`)
			return
		}

		resp := responses[index]
		for name, value := range resp.header {
			w.Header().Set(name, value)
		}
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(resp.status)
		if resp.body != "" {
			_, _ = io.WriteString(w, resp.body)
		}
	}))
	t.Cleanup(srv.Close)

	return NewClientWithBaseURL(testToken, srv.URL), log
}

// hitSensingClient returns a client whose server never serves a valid reply and
// a counter of the requests it saw. It backs the "validation happens before the
// network" assertions.
func hitSensingClient(t *testing.T) (*Client, *requestLog) {
	t.Helper()

	log := &requestLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		log.record(scriptedRequest{
			method:   r.Method,
			path:     r.URL.Path,
			rawQuery: r.URL.RawQuery,
			query:    r.URL.Query(),
			header:   r.Header.Clone(),
			body:     raw,
		})
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	return NewClientWithBaseURL(testToken, srv.URL), log
}

// assertQueryParams verifies that the request carried each expected query value.
func assertQueryParams(t *testing.T, req scriptedRequest, want map[string]string) {
	t.Helper()

	for name, value := range want {
		if got := req.query.Get(name); got != value {
			t.Errorf("query %q = %q, want %q (raw query %q)", name, got, value, req.rawQuery)
		}
	}
}

// fullAdvisoryJSON is a realistic GET .../security-advisories/{ghsa_id} body.
const fullAdvisoryJSON = `{
  "ghsa_id": "GHSA-abcd-1234-efgh",
  "cve_id": "CVE-2024-0001",
  "url": "https://api.github.com/repos/octocat/hello-world/security-advisories/GHSA-abcd-1234-efgh",
  "html_url": "https://github.com/octocat/hello-world/security-advisories/GHSA-abcd-1234-efgh",
  "summary": "Reflected XSS in search",
  "description": "A reflected XSS issue exists in the search box.",
  "severity": "high",
  "state": "published",
  "created_at": "2024-05-01T10:00:00Z",
  "updated_at": "2024-05-02T11:00:00Z",
  "published_at": "2024-05-03T12:00:00Z",
  "author": {"login": "octocat", "id": 1, "html_url": "https://github.com/octocat", "type": "User"},
  "publisher": {"login": "gh-security", "id": 2, "type": "User"},
  "identifiers": [{"type": "GHSA", "value": "GHSA-abcd-1234-efgh"}, {"type": "CVE", "value": "CVE-2024-0001"}],
  "vulnerabilities": [
    {
      "package": {"ecosystem": "npm", "name": "hello-world"},
      "vulnerable_version_range": "< 1.2.3",
      "patched_versions": "1.2.3",
      "vulnerable_functions": ["search"]
    }
  ],
  "cvss": {"vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "score": 6.1},
  "cvss_severities": {
    "cvss_v3": {"vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "score": 6.1},
    "cvss_v4": {"vector_string": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", "score": 5.3}
  },
  "cwe_ids": ["CWE-79", "CWE-80"],
  "cwes": [{"cwe_id": "CWE-79", "name": "Cross-site Scripting"}],
  "credits": [{"login": "finder", "type": "reporter"}],
  "credits_detailed": [{"user": {"login": "finder", "id": 3}, "type": "reporter"}],
  "collaborating_users": [{"login": "helper", "id": 4, "type": "User"}],
  "collaborating_teams": [{"id": 5, "name": "Security", "slug": "security"}],
  "submission": {"accepted": true},
  "private_fork": {
    "id": 6,
    "full_name": "octocat/hello-world-private",
    "html_url": "https://github.com/octocat/hello-world-private",
    "owner": {"login": "octocat", "id": 1}
  }
}`

// advisoryListJSON is a one-item list payload.
const advisoryListJSON = `[
  {
    "ghsa_id": "GHSA-abcd-1234-efgh",
    "summary": "Reflected XSS in search",
    "severity": "high",
    "state": "published"
  },
  {
    "ghsa_id": "GHSA-zzzz-9999-yyyy",
    "summary": "Open redirect",
    "severity": "low",
    "state": "draft"
  }
]`

func TestListAdvisoriesHappyPath(t *testing.T) {
	client, log := newScriptedClient(t, scriptedResponse{status: http.StatusOK, body: advisoryListJSON})

	page, err := client.ListAdvisories(context.Background(), "octocat", "hello-world", AdvisoryListOptions{
		State:     StatePublished,
		Sort:      "updated",
		Direction: "desc",
		PerPage:   50,
		Page:      2,
	})
	if err != nil {
		t.Fatalf("ListAdvisories returned error: %v", err)
	}

	req := log.last(t)
	if req.method != http.MethodGet {
		t.Errorf("method = %q, want %q", req.method, http.MethodGet)
	}
	if want := "/repos/octocat/hello-world/security-advisories"; req.path != want {
		t.Errorf("path = %q, want %q", req.path, want)
	}
	assertQueryParams(t, req, map[string]string{
		"state":     "published",
		"sort":      "updated",
		"direction": "desc",
		"per_page":  "50",
		"page":      "2",
	})
	assertGitHubRequestHeaders(t, req.header)

	if len(page.Items) != 2 {
		t.Fatalf("len(Items) = %d, want 2", len(page.Items))
	}
	if got, want := page.Items[0].GHSAID, "GHSA-abcd-1234-efgh"; got != want {
		t.Errorf("Items[0].GHSAID = %q, want %q", got, want)
	}
	if got, want := page.Items[1].State, "draft"; got != want {
		t.Errorf("Items[1].State = %q, want %q", got, want)
	}
	if got, want := page.TotalCount, -1; got != want {
		t.Errorf("TotalCount = %d, want %d (GitHub reports no total)", got, want)
	}
	if page.NextPage != 0 || page.HasMore {
		t.Errorf("NextPage = %d, HasMore = %v; want 0/false without a Link header", page.NextPage, page.HasMore)
	}
}

func TestListAdvisoriesDefaults(t *testing.T) {
	tests := []struct {
		name        string
		opts        AdvisoryListOptions
		wantPerPage string
		wantPage    string
	}{
		{name: "zero values", opts: AdvisoryListOptions{}, wantPerPage: "30", wantPage: "1"},
		{name: "negative per page and page", opts: AdvisoryListOptions{PerPage: -5, Page: -2}, wantPerPage: "30", wantPage: "1"},
		{name: "oversized per page", opts: AdvisoryListOptions{PerPage: 500}, wantPerPage: "100", wantPage: "1"},
		{name: "boundary per page", opts: AdvisoryListOptions{PerPage: 100, Page: 3}, wantPerPage: "100", wantPage: "3"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, log := newScriptedClient(t, scriptedResponse{status: http.StatusOK, body: `[]`})

			if _, err := client.ListAdvisories(context.Background(), "octocat", "hello-world", tc.opts); err != nil {
				t.Fatalf("ListAdvisories returned error: %v", err)
			}
			req := log.last(t)
			assertQueryParams(t, req, map[string]string{"per_page": tc.wantPerPage, "page": tc.wantPage})
			if _, present := req.query["state"]; present {
				t.Errorf("state filter unexpectedly sent: %q", req.rawQuery)
			}
			if _, present := req.query["sort"]; present {
				t.Errorf("sort param unexpectedly sent: %q", req.rawQuery)
			}
		})
	}
}

func TestListAdvisoriesPagination(t *testing.T) {
	link := `<https://api.github.com/repos/octocat/hello-world/security-advisories?per_page=30&page=3>; rel="next", ` +
		`<https://api.github.com/repos/octocat/hello-world/security-advisories?per_page=30&page=9>; rel="last"`
	client, _ := newScriptedClient(t, scriptedResponse{
		status: http.StatusOK,
		body:   advisoryListJSON,
		header: map[string]string{"Link": link},
	})

	page, err := client.ListAdvisories(context.Background(), "octocat", "hello-world", AdvisoryListOptions{Page: 2})
	if err != nil {
		t.Fatalf("ListAdvisories returned error: %v", err)
	}
	if got, want := page.NextPage, 3; got != want {
		t.Errorf("NextPage = %d, want %d", got, want)
	}
	if !page.HasMore {
		t.Error("HasMore = false, want true when a rel=\"next\" link is present")
	}
	if got, want := page.TotalCount, -1; got != want {
		t.Errorf("TotalCount = %d, want %d", got, want)
	}
}

func TestListAdvisoriesNullAndEmptyBodies(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "json null", body: "null"},
		{name: "empty array", body: "[]"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := newScriptedClient(t, scriptedResponse{status: http.StatusOK, body: tc.body})

			page, err := client.ListAdvisories(context.Background(), "octocat", "hello-world", AdvisoryListOptions{})
			if err != nil {
				t.Fatalf("ListAdvisories returned error: %v", err)
			}
			if page.Items == nil {
				t.Fatal("Items is nil, want an empty slice so callers can range over it")
			}
			if len(page.Items) != 0 {
				t.Errorf("len(Items) = %d, want 0", len(page.Items))
			}
			if page.TotalCount != -1 {
				t.Errorf("TotalCount = %d, want -1", page.TotalCount)
			}
			if page.HasMore || page.NextPage != 0 {
				t.Errorf("NextPage = %d, HasMore = %v; want 0/false", page.NextPage, page.HasMore)
			}
		})
	}
}

func TestListAdvisoriesRejectsInvalidInputWithoutNetwork(t *testing.T) {
	client, log := hitSensingClient(t)

	tests := []struct {
		name  string
		owner string
		repo  string
		opts  AdvisoryListOptions
	}{
		{name: "invalid state", owner: "octocat", repo: "hello-world", opts: AdvisoryListOptions{State: AdvisoryState("published-ish")}},
		{name: "invalid sort", owner: "octocat", repo: "hello-world", opts: AdvisoryListOptions{Sort: "relevance"}},
		{name: "invalid direction", owner: "octocat", repo: "hello-world", opts: AdvisoryListOptions{Direction: "sideways"}},
		{name: "empty owner", owner: "", repo: "hello-world"},
		{name: "empty repo", owner: "octocat", repo: ""},
		{name: "owner with space", owner: "octo cat", repo: "hello-world"},
		{name: "repo with slash", owner: "octocat", repo: "hello/world"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			page, err := client.ListAdvisories(context.Background(), tc.owner, tc.repo, tc.opts)
			if err == nil {
				t.Fatal("expected a validation error, got nil")
			}
			if _, ok := AsAPIError(err); ok {
				t.Fatalf("validation error must not be an *APIError: %v", err)
			}
			if page.Items != nil {
				t.Errorf("Items = %#v, want nil on error", page.Items)
			}
		})
	}

	if got := log.count(); got != 0 {
		t.Errorf("server received %d requests, want 0: validation must run before the network", got)
	}
}

func TestListAdvisoriesAPIError(t *testing.T) {
	client, _ := newScriptedClient(t, scriptedResponse{
		status: http.StatusForbidden,
		body:   `{"message":"Resource not accessible by integration"}`,
	})

	page, err := client.ListAdvisories(context.Background(), "octocat", "hello-world", AdvisoryListOptions{})
	if err == nil {
		t.Fatalf("expected an error, got %#v", page)
	}
	if page.Items != nil {
		t.Errorf("Items = %#v, want nil on error", page.Items)
	}
	apiErr, ok := AsAPIError(err)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if !apiErr.IsForbidden() {
		t.Errorf("IsForbidden() = false, want true (status %d)", apiErr.StatusCode)
	}
	if got, want := apiErr.Method, http.MethodGet; got != want {
		t.Errorf("APIError.Method = %q, want %q", got, want)
	}
}

func TestGetAdvisoryHappyPath(t *testing.T) {
	client, log := newScriptedClient(t, scriptedResponse{status: http.StatusOK, body: fullAdvisoryJSON})

	adv, err := client.GetAdvisory(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh")
	if err != nil {
		t.Fatalf("GetAdvisory returned error: %v", err)
	}
	if adv == nil {
		t.Fatal("GetAdvisory returned a nil advisory")
	}

	req := log.last(t)
	if req.method != http.MethodGet {
		t.Errorf("method = %q, want %q", req.method, http.MethodGet)
	}
	// The id is normalised to the canonical upper-case form in the URL path.
	if want := "/repos/octocat/hello-world/security-advisories/GHSA-abcd-1234-efgh"; req.path != want {
		t.Errorf("path = %q, want %q", req.path, want)
	}

	if got, want := adv.GHSAID, "GHSA-abcd-1234-efgh"; got != want {
		t.Errorf("GHSAID = %q, want %q", got, want)
	}
	if got, want := adv.CVEID, "CVE-2024-0001"; got != want {
		t.Errorf("CVEID = %q, want %q", got, want)
	}
	if got, want := adv.Severity, "high"; got != want {
		t.Errorf("Severity = %q, want %q", got, want)
	}
	if got, want := adv.State, "published"; got != want {
		t.Errorf("State = %q, want %q", got, want)
	}
	if got, want := adv.AuthorLogin(), "octocat"; got != want {
		t.Errorf("AuthorLogin() = %q, want %q", got, want)
	}
	if len(adv.Vulnerabilities) != 1 {
		t.Fatalf("len(Vulnerabilities) = %d, want 1", len(adv.Vulnerabilities))
	}
	if got, want := adv.Vulnerabilities[0].Package.String(), "npm:hello-world"; got != want {
		t.Errorf("Package = %q, want %q", got, want)
	}
	if got, want := adv.Vulnerabilities[0].PatchedVersions, "1.2.3"; got != want {
		t.Errorf("PatchedVersions = %q, want %q", got, want)
	}
	if adv.CVSS == nil {
		t.Fatal("CVSS is nil, want the decoded vector")
	}
	if got, want := adv.CVSS.Score, 6.1; got != want {
		t.Errorf("CVSS.Score = %v, want %v", got, want)
	}
	if adv.CVSSSeverities == nil || adv.CVSSSeverities.CVSSV4 == nil {
		t.Fatal("CVSSSeverities.CVSSV4 is nil, want the decoded v4 vector")
	}
	if got, want := adv.CVSSScoreText(), "6.1"; got != want {
		t.Errorf("CVSSScoreText() = %q, want %q", got, want)
	}
	if len(adv.CWEIDs) != 2 || adv.CWEIDs[0] != "CWE-79" {
		t.Errorf("CWEIDs = %#v, want [CWE-79 CWE-80]", adv.CWEIDs)
	}
	if len(adv.Credits) != 1 || adv.Credits[0].Login != "finder" {
		t.Errorf("Credits = %#v, want one credit for finder", adv.Credits)
	}
	if len(adv.CollaboratingUsers) != 1 || adv.CollaboratingUsers[0].Login != "helper" {
		t.Errorf("CollaboratingUsers = %#v, want one collaborator helper", adv.CollaboratingUsers)
	}
	if len(adv.CollaboratingTeams) != 1 || adv.CollaboratingTeams[0].Slug != "security" {
		t.Errorf("CollaboratingTeams = %#v, want the security team", adv.CollaboratingTeams)
	}
	if adv.Submission == nil || !adv.Submission.Accepted {
		t.Errorf("Submission = %#v, want accepted", adv.Submission)
	}
	if adv.PrivateFork == nil || adv.PrivateFork.ID != 6 {
		t.Fatalf("PrivateFork = %#v, want id 6", adv.PrivateFork)
	}
	if got, want := adv.PrivateFork.FullName, "octocat/hello-world-private"; got != want {
		t.Errorf("PrivateFork.FullName = %q, want %q", got, want)
	}
	if got, want := adv.AffectedSummary(), "npm:hello-world < 1.2.3"; got != want {
		t.Errorf("AffectedSummary() = %q, want %q", got, want)
	}
	if adv.CVEStatus() != CVEAssigned {
		t.Errorf("CVEStatus() = %q, want %q", adv.CVEStatus(), CVEAssigned)
	}
	if adv.IsOpen() {
		t.Error("IsOpen() = true for a published advisory, want false")
	}
}

func TestGetAdvisoryNormalisesGHSAIDCase(t *testing.T) {
	client, log := newScriptedClient(t, scriptedResponse{status: http.StatusOK, body: fullAdvisoryJSON})

	if _, err := client.GetAdvisory(context.Background(), "octocat", "hello-world", "ghsa-abcd-1234-efgh"); err != nil {
		t.Fatalf("GetAdvisory returned error: %v", err)
	}
	req := log.last(t)
	if want := "/repos/octocat/hello-world/security-advisories/GHSA-abcd-1234-efgh"; req.path != want {
		t.Errorf("path = %q, want %q (lower-case input must be normalised to upper case)", req.path, want)
	}
}

func TestGetAdvisoryNotFound(t *testing.T) {
	client, _ := newScriptedClient(t, scriptedResponse{
		status: http.StatusNotFound,
		body:   `{"message":"Not Found","documentation_url":"https://docs.github.com/rest"}`,
	})

	adv, err := client.GetAdvisory(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh")
	if err == nil {
		t.Fatalf("expected an error, got %#v", adv)
	}
	if adv != nil {
		t.Errorf("advisory = %#v, want nil on error", adv)
	}
	apiErr, ok := AsAPIError(err)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if !apiErr.IsNotFound() {
		t.Errorf("IsNotFound() = false, want true (status %d)", apiErr.StatusCode)
	}
	var target *APIError
	if !errors.As(err, &target) {
		t.Errorf("errors.As could not unwrap %v", err)
	}
}

func TestGetAdvisoryRejectsInvalidInputWithoutNetwork(t *testing.T) {
	client, log := hitSensingClient(t)

	tests := []struct {
		name   string
		owner  string
		repo   string
		ghsaID string
	}{
		{name: "empty ghsa", owner: "octocat", repo: "hello-world", ghsaID: ""},
		{name: "short ghsa", owner: "octocat", repo: "hello-world", ghsaID: "GHSA-abcd-1234"},
		{name: "cve instead of ghsa", owner: "octocat", repo: "hello-world", ghsaID: "CVE-2024-0001"},
		{name: "path traversal attempt", owner: "octocat", repo: "hello-world", ghsaID: "../../user"},
		{name: "invalid owner", owner: "octo cat", repo: "hello-world", ghsaID: "GHSA-abcd-1234-efgh"},
		{name: "invalid repo", owner: "octocat", repo: "..", ghsaID: "GHSA-abcd-1234-efgh"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			adv, err := client.GetAdvisory(context.Background(), tc.owner, tc.repo, tc.ghsaID)
			if err == nil {
				t.Fatalf("expected a validation error, got %#v", adv)
			}
			if _, ok := AsAPIError(err); ok {
				t.Fatalf("validation error must not be an *APIError: %v", err)
			}
		})
	}

	if got := log.count(); got != 0 {
		t.Errorf("server received %d requests, want 0: validation must run before the network", got)
	}
}

func TestGetAdvisoryEmptyPayloadIsError(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "empty body", body: ""},
		{name: "json null", body: "null"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := newScriptedClient(t, scriptedResponse{status: http.StatusOK, body: tc.body})

			adv, err := client.GetAdvisory(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh")
			if err == nil {
				t.Fatalf("expected an error for a %q body, got %#v", tc.body, adv)
			}
			if adv != nil {
				t.Errorf("advisory = %#v, want nil", adv)
			}
			if _, ok := AsAPIError(err); !ok {
				t.Fatalf("expected *APIError, got %T: %v", err, err)
			}
		})
	}
}

func TestGetAdvisoryMalformedPayloadIsError(t *testing.T) {
	client, _ := newScriptedClient(t, scriptedResponse{status: http.StatusOK, body: `{"ghsa_id": 42}`})

	adv, err := client.GetAdvisory(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh")
	if err == nil {
		t.Fatalf("expected an error, got %#v", adv)
	}
	apiErr, ok := AsAPIError(err)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, http.StatusOK)
	}
	if apiErr.Body == "" {
		t.Error("APIError.Body is empty, want a snippet of the offending payload")
	}
}

func TestAdvisoryListJSONDecodesBothStates(t *testing.T) {
	client, _ := newScriptedClient(t, scriptedResponse{status: http.StatusOK, body: advisoryListJSON})

	page, err := client.ListAdvisories(context.Background(), "octocat", "hello-world", AdvisoryListOptions{})
	if err != nil {
		t.Fatalf("ListAdvisories returned error: %v", err)
	}

	states := make([]AdvisoryState, 0, len(page.Items))
	for i := range page.Items {
		states = append(states, page.Items[i].AdvisoryStateValue())
	}
	want := []AdvisoryState{StatePublished, StateDraft}
	if len(states) != len(want) {
		t.Fatalf("states = %#v, want %#v", states, want)
	}
	for i := range want {
		if states[i] != want[i] {
			t.Errorf("states[%d] = %q, want %q", i, states[i], want[i])
		}
	}

	encoded, err := json.Marshal(page.Items[0])
	if err != nil {
		t.Fatalf("re-encode item: %v", err)
	}
	if !strings.Contains(string(encoded), `"ghsa_id":"GHSA-abcd-1234-efgh"`) {
		t.Errorf("re-encoded item lost its id: %s", string(encoded))
	}
}
