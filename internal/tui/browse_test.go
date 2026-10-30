package tui

// Tests for the advisory browser. The interactive wrappers need a TTY, so they
// are only exercised indirectly (they must compile and must not be reachable
// from the pure helpers below); the data paths and the renderers are tested
// directly against an httptest server.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/yukiu/ghsec/internal/api"
)

// browseSampleGHSA is a syntactically valid advisory id for the fixtures.
const (
	browseSampleGHSA  = "GHSA-abcd-1234-wxyz"
	browseSampleGHSA2 = "GHSA-efgh-5678-stuv"
)

// browseServerRecords counts the requests a fake GitHub server received.
type browseServerRecords struct {
	mu    sync.Mutex
	paths []string
	query []string
}

// record stores one request and returns its query string.
func (r *browseServerRecords) record(req *http.Request) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.paths = append(r.paths, req.URL.Path)
	r.query = append(r.query, req.URL.RawQuery)
	return req.URL.Query().Get("page")
}

// count returns how many requests were recorded.
func (r *browseServerRecords) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.paths)
}

// queries returns a copy of the recorded query strings.
func (r *browseServerRecords) queries() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.query...)
}

// browseAdvisoryJSON renders one advisory object for a fake API response.
func browseAdvisoryJSON(ghsaID, summary, severity, state, cveID string) string {
	return fmt.Sprintf(`{
		"ghsa_id": %q,
		"cve_id": %q,
		"summary": %q,
		"description": "A detailed description.",
		"severity": %q,
		"state": %q,
		"html_url": "https://github.com/octocat/hello-world/security/advisories/%s",
		"created_at": "2024-01-02T03:04:05Z",
		"updated_at": "2024-02-03T04:05:06Z",
		"published_at": "2024-02-01T00:00:00Z",
		"author": {"login": "octocat"},
		"vulnerabilities": [
			{"package": {"ecosystem": "npm", "name": "left-pad"}, "vulnerable_version_range": "< 1.2.3"}
		],
		"cvss": {"vector_string": "CVSS:3.1/AV:N/AC:L", "score": 9.8},
		"cwe_ids": ["CWE-79"],
		"credits": [{"login": "hubot"}],
		"collaborating_users": [{"login": "monalisa"}]
	}`, ghsaID, cveID, summary, severity, state, ghsaID)
}

// browseCommentsPath is the comment collection path for the sample advisory.
func browseCommentsPath(owner, repo, ghsaID string) string {
	return "/repos/" + owner + "/" + repo + "/security-advisories/" + ghsaID + "/comments"
}

func TestFetchAdvisoriesPagesUntilLimit(t *testing.T) {
	rec := &browseServerRecords{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := rec.record(r)
		w.Header().Set("Content-Type", "application/json")
		switch page {
		case "1":
			// Two items on page 1, and a Link header advertising page 2.
			w.Header().Set("Link", fmt.Sprintf(`<%s%s?page=2>; rel="next"`, "http://"+r.Host, r.URL.Path))
			fmt.Fprint(w, "["+browseAdvisoryJSON(browseSampleGHSA, "first", "high", "published", "")+","+
				browseAdvisoryJSON(browseSampleGHSA2, "second", "low", "draft", "")+"]")
		case "2":
			fmt.Fprint(w, "["+browseAdvisoryJSON("GHSA-ijkl-9012-mnop", "third", "critical", "triage", "CVE-2024-1234")+"]")
		default:
			fmt.Fprint(w, "[]")
		}
	}))
	defer srv.Close()

	client := api.NewClientWithBaseURL("ghp_test", srv.URL)

	advisories, err := FetchAdvisories(context.Background(), client, "octocat", "hello-world", "", 3)
	if err != nil {
		t.Fatalf("FetchAdvisories() error = %v", err)
	}
	if len(advisories) != 3 {
		t.Fatalf("got %d advisories, want 3", len(advisories))
	}
	// Order must be preserved across pages.
	wantOrder := []string{browseSampleGHSA, browseSampleGHSA2, "GHSA-ijkl-9012-mnop"}
	for i, want := range wantOrder {
		if got := advisories[i].GHSAID; got != want {
			t.Fatalf("advisories[%d].GHSAID = %q, want %q", i, got, want)
		}
	}
	// Page 2 was needed for the third item, so two requests were made.
	if got := rec.count(); got != 2 {
		t.Fatalf("server received %d requests, want 2", got)
	}
	// The second request must ask for the next page.
	if queries := rec.queries(); !strings.Contains(queries[1], "page=2") {
		t.Fatalf("second request query = %q, want page=2", queries[1])
	}
}

func TestFetchAdvisoriesRespectsLimit(t *testing.T) {
	rec := &browseServerRecords{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record(r)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Link", fmt.Sprintf(`<%s%s?page=2>; rel="next"`, "http://"+r.Host, r.URL.Path))
		fmt.Fprint(w, "["+browseAdvisoryJSON(browseSampleGHSA, "first", "high", "published", "")+","+
			browseAdvisoryJSON(browseSampleGHSA2, "second", "low", "draft", "")+"]")
	}))
	defer srv.Close()

	client := api.NewClientWithBaseURL("ghp_test", srv.URL)

	advisories, err := FetchAdvisories(context.Background(), client, "octocat", "hello-world", "", 2)
	if err != nil {
		t.Fatalf("FetchAdvisories() error = %v", err)
	}
	if len(advisories) != 2 {
		t.Fatalf("got %d advisories, want 2", len(advisories))
	}
	// Reaching the limit on the first page must stop the walk: one request only.
	if got := rec.count(); got != 1 {
		t.Fatalf("server received %d requests, want 1 (limit reached on page 1)", got)
	}
}

func TestFetchAdvisoriesDefaultsLimit(t *testing.T) {
	rec := &browseServerRecords{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record(r)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "[]")
	}))
	defer srv.Close()

	client := api.NewClientWithBaseURL("ghp_test", srv.URL)

	advisories, err := FetchAdvisories(context.Background(), client, "octocat", "hello-world", "", 0)
	if err != nil {
		t.Fatalf("FetchAdvisories() error = %v", err)
	}
	if advisories == nil {
		t.Fatal("FetchAdvisories() returned a nil slice, want an empty slice")
	}
	if len(advisories) != 0 {
		t.Fatalf("got %d advisories, want 0", len(advisories))
	}
	if got := rec.count(); got != 1 {
		t.Fatalf("server received %d requests, want 1", got)
	}
}

func TestFetchAdvisoriesEmptyRepo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "[]")
	}))
	defer srv.Close()

	client := api.NewClientWithBaseURL("ghp_test", srv.URL)

	advisories, err := FetchAdvisories(context.Background(), client, "octocat", "hello-world", api.StatePublished, 50)
	if err != nil {
		t.Fatalf("FetchAdvisories() error = %v", err)
	}
	if advisories == nil {
		t.Fatal("FetchAdvisories() returned nil, want an empty slice")
	}
	if len(advisories) != 0 {
		t.Fatalf("got %d advisories, want 0", len(advisories))
	}
}

func TestFetchAdvisoriesForwardsStateFilter(t *testing.T) {
	rec := &browseServerRecords{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record(r)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "[]")
	}))
	defer srv.Close()

	client := api.NewClientWithBaseURL("ghp_test", srv.URL)
	if _, err := FetchAdvisories(context.Background(), client, "octocat", "hello-world", api.StateTriage, 10); err != nil {
		t.Fatalf("FetchAdvisories() error = %v", err)
	}
	queries := rec.queries()
	if len(queries) != 1 {
		t.Fatalf("server received %d requests, want 1", len(queries))
	}
	if !strings.Contains(queries[0], "state=triage") {
		t.Fatalf("query %q does not carry the triage filter", queries[0])
	}
}

func TestFetchAdvisoriesNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"Not Found"}`)
	}))
	defer srv.Close()

	client := api.NewClientWithBaseURL("ghp_test", srv.URL)

	advisories, err := FetchAdvisories(context.Background(), client, "octocat", "missing", "", 10)
	if err == nil {
		t.Fatal("FetchAdvisories() error = nil, want a 404 error")
	}
	if advisories != nil {
		t.Fatalf("FetchAdvisories() returned %d advisories on error, want nil", len(advisories))
	}
	apiErr, ok := api.AsAPIError(err)
	if !ok {
		t.Fatalf("error %v is not an *api.APIError", err)
	}
	if apiErr.StatusCode != http.StatusNotFound {
		t.Fatalf("StatusCode = %d, want 404", apiErr.StatusCode)
	}
}

func TestFetchAdvisoriesNilClient(t *testing.T) {
	if _, err := FetchAdvisories(context.Background(), nil, "octocat", "hello-world", "", 10); err == nil {
		t.Fatal("FetchAdvisories(nil client) error = nil, want a friendly error")
	}
}

func TestFetchAdvisoriesCancelledContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "[]")
	}))
	defer srv.Close()

	client := api.NewClientWithBaseURL("ghp_test", srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := FetchAdvisories(ctx, client, "octocat", "hello-world", "", 10); err == nil {
		t.Fatal("FetchAdvisories(cancelled ctx) error = nil, want context.Canceled")
	}
}

func TestFetchCommentsSinglePage(t *testing.T) {
	// The API layer normalises a GHSA id to upper case before building the path.
	rec := &browseServerRecords{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record(r)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[
			{"id": 1, "body": "Thanks for the report", "user": {"login": "octocat"},
			 "created_at": "2024-03-01T00:00:00Z", "author_association": "MEMBER"},
			{"id": 2, "body": "Fixed in 1.2.3", "user": {"login": "hubot"},
			 "created_at": "2024-03-02T00:00:00Z", "author_association": "COLLABORATOR"}
		]`)
	}))
	defer srv.Close()

	client := api.NewClientWithBaseURL("ghp_test", srv.URL)

	comments, err := FetchComments(context.Background(), client, "octocat", "hello-world", browseSampleGHSA)
	if err != nil {
		t.Fatalf("FetchComments() error = %v", err)
	}
	if len(comments) != 2 {
		t.Fatalf("got %d comments, want 2", len(comments))
	}
	if got := comments[0].AuthorLogin(); got != "octocat" {
		t.Fatalf("comments[0] author = %q, want octocat", got)
	}
	wantPath := browseCommentsPath("octocat", "hello-world", browseSampleGHSA)
	if got := rec.paths[0]; got != wantPath {
		t.Fatalf("request path = %q, want %q", got, wantPath)
	}
	if got := rec.count(); got != 1 {
		t.Fatalf("server received %d requests, want 1", got)
	}
}

func TestFetchCommentsPaginates(t *testing.T) {
	rec := &browseServerRecords{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := rec.record(r)
		w.Header().Set("Content-Type", "application/json")
		switch page {
		case "1":
			w.Header().Set("Link", fmt.Sprintf(`<%s%s?page=2>; rel="next"`, "http://"+r.Host, r.URL.Path))
			fmt.Fprint(w, `[{"id": 1, "body": "first", "user": {"login": "octocat"}}]`)
		case "2":
			fmt.Fprint(w, `[{"id": 2, "body": "second", "user": {"login": "hubot"}}]`)
		default:
			fmt.Fprint(w, "[]")
		}
	}))
	defer srv.Close()

	client := api.NewClientWithBaseURL("ghp_test", srv.URL)

	comments, err := FetchComments(context.Background(), client, "octocat", "hello-world", browseSampleGHSA)
	if err != nil {
		t.Fatalf("FetchComments() error = %v", err)
	}
	if len(comments) != 2 {
		t.Fatalf("got %d comments, want 2", len(comments))
	}
	if comments[0].Body != "first" || comments[1].Body != "second" {
		t.Fatalf("comment order = %q, %q; want first, second", comments[0].Body, comments[1].Body)
	}
	if got := rec.count(); got != 2 {
		t.Fatalf("server received %d requests, want 2", got)
	}
}

func TestFetchCommentsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "[]")
	}))
	defer srv.Close()

	client := api.NewClientWithBaseURL("ghp_test", srv.URL)

	comments, err := FetchComments(context.Background(), client, "octocat", "hello-world", browseSampleGHSA)
	if err != nil {
		t.Fatalf("FetchComments() error = %v", err)
	}
	if comments == nil {
		t.Fatal("FetchComments() returned nil, want an empty slice")
	}
	if len(comments) != 0 {
		t.Fatalf("got %d comments, want 0", len(comments))
	}
}

func TestFetchCommentsRejectsEmptyAdvisoryID(t *testing.T) {
	// An empty id must be rejected locally: no request may reach the network.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request to %s", r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := api.NewClientWithBaseURL("ghp_test", srv.URL)
	if _, err := FetchComments(context.Background(), client, "octocat", "hello-world", "   "); err == nil {
		t.Fatal("FetchComments() error = nil, want a validation error")
	}
}

func TestFetchCommentsNotFoundPropagatesAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"Not Found"}`)
	}))
	defer srv.Close()

	client := api.NewClientWithBaseURL("ghp_test", srv.URL)

	_, err := FetchComments(context.Background(), client, "octocat", "hello-world", browseSampleGHSA)
	if err == nil {
		t.Fatal("FetchComments() error = nil, want a 404 error")
	}
	apiErr, ok := api.AsAPIError(err)
	if !ok {
		t.Fatalf("error %v is not an *api.APIError", err)
	}
	if apiErr.StatusCode != http.StatusNotFound {
		t.Fatalf("StatusCode = %d, want 404", apiErr.StatusCode)
	}
}

// browseFullAdvisory builds a fully populated advisory for renderer tests.
func browseFullAdvisory() *api.AdvisoryDetail {
	return &api.AdvisoryDetail{
		GHSAID:             browseSampleGHSA,
		CVEID:              "CVE-2024-9999",
		HTMLURL:            "https://github.com/octocat/hello-world/security/advisories/" + browseSampleGHSA,
		Summary:            "Path traversal in the archive extractor",
		Description:        "## Impact\n\nAn attacker can escape the target directory.\n\n## Patches\n\nUpgrade to 1.2.3.",
		Severity:           "high",
		State:              "published",
		CreatedAt:          "2024-01-02T03:04:05Z",
		UpdatedAt:          "2024-02-03T04:05:06Z",
		PublishedAt:        "2024-02-01T00:00:00Z",
		Author:             &api.SimpleUser{Login: "octocat"},
		CWEIDs:             []string{"CWE-22"},
		Credits:            []api.Credit{{Login: "hubot"}},
		CollaboratingUsers: []api.SimpleUser{{Login: "monalisa"}},
		Vulnerabilities: []api.Vulnerability{{
			Package:                api.Package{Ecosystem: "npm", Name: "left-pad"},
			VulnerableVersionRange: "< 1.2.3",
		}},
		CVSS: &api.CVSS{VectorString: "CVSS:3.1/AV:N/AC:L", Score: 8.1},
	}
}

func TestRenderAdvisoryDetailFull(t *testing.T) {
	out := RenderAdvisoryDetail(browseFullAdvisory(), 80)
	if out == "" {
		t.Fatal("RenderAdvisoryDetail() returned an empty string")
	}
	text := mdStripEscape(out)

	for _, want := range []string{
		browseSampleGHSA,              // box title
		"CVE-2024-9999",               // CVE id
		"HIGH",                        // severity badge
		"PUBLISHED",                   // state badge
		"npm:left-pad < 1.2.3",        // affected package summary
		"octocat",                     // author
		"hubot",                       // credit
		"monalisa",                    // collaborator
		"CWE-22",                      // cwe
		"8.1",                         // cvss score
		"Path traversal",              // summary
		"escape the target directory", // part of the description
		"Impact",                      // a description heading
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered detail does not contain %q:\n%s", want, text)
		}
	}
}

func TestRenderAdvisoryDetailMissingCVE(t *testing.T) {
	a := browseFullAdvisory()
	a.CVEID = ""

	text := mdStripEscape(RenderAdvisoryDetail(a, 80))
	if !strings.Contains(strings.ToLower(text), "not assigned") {
		t.Fatalf("rendered detail does not explain the missing CVE:\n%s", text)
	}
}

func TestRenderAdvisoryDetailNil(t *testing.T) {
	out := RenderAdvisoryDetail(nil, 80)
	if out == "" {
		t.Fatal("RenderAdvisoryDetail(nil) returned an empty string")
	}
	if !strings.Contains(strings.ToLower(mdStripEscape(out)), "no") {
		t.Fatalf("RenderAdvisoryDetail(nil) = %q, want it to mention there is no advisory", out)
	}
}

func TestRenderAdvisoryDetailZeroValue(t *testing.T) {
	// An all-empty advisory must still render, without panicking.
	out := RenderAdvisoryDetail(&api.AdvisoryDetail{}, 80)
	if out == "" {
		t.Fatal("RenderAdvisoryDetail(&{}) returned an empty string")
	}
	text := mdStripEscape(out)
	if !strings.Contains(strings.ToLower(text), "not assigned") {
		t.Fatalf("zero advisory does not report a missing CVE:\n%s", text)
	}
}

func TestRenderAdvisoryDetailWidths(t *testing.T) {
	for _, width := range []int{0, -1, -200, 1, 20, 40, 80, 200} {
		out := RenderAdvisoryDetail(browseFullAdvisory(), width)
		if out == "" {
			t.Fatalf("RenderAdvisoryDetail(width=%d) returned an empty string", width)
		}
		if !strings.Contains(mdStripEscape(out), browseSampleGHSA) {
			t.Fatalf("RenderAdvisoryDetail(width=%d) lost the advisory id", width)
		}
	}
}

func TestRenderAdvisoryDetailArbitraryTextIsSafe(t *testing.T) {
	// Advisory bodies are user-authored; they must be displayed, never executed
	// as terminal control sequences.
	a := browseFullAdvisory()
	a.Summary = "\x1b[2Jwiped"
	a.Description = "\x1b]0;pwned\x07body"

	out := RenderAdvisoryDetail(a, 80)
	for _, bad := range []string{"\x1b[2J", "\x1b[?1049h", "\x1b[?25l"} {
		if strings.Contains(out, bad) {
			t.Fatalf("rendered detail contains control sequence %q", bad)
		}
	}
}

func TestRenderCommentThreadTwoComments(t *testing.T) {
	comments := []api.Comment{
		{
			ID:                1,
			Body:              "Thanks for the report, we are looking into it.",
			User:              &api.SimpleUser{Login: "octocat"},
			CreatedAt:         "2024-03-01T00:00:00Z",
			AuthorAssociation: "MEMBER",
		},
		{
			ID:                2,
			Body:              "Fixed and published in 1.2.3.",
			User:              &api.SimpleUser{Login: "hubot"},
			CreatedAt:         "2024-03-02T00:00:00Z",
			AuthorAssociation: "COLLABORATOR",
		},
	}

	out := RenderCommentThread(comments, 80)
	if out == "" {
		t.Fatal("RenderCommentThread() returned an empty string")
	}
	text := mdStripEscape(out)
	for _, want := range []string{
		"octocat", "hubot",
		"looking into it", "Fixed and published",
		"member", "collaborator",
		"2024-03-01",
	} {
		if !strings.Contains(strings.ToLower(text), strings.ToLower(want)) {
			t.Fatalf("thread does not contain %q:\n%s", want, text)
		}
	}
}

func TestRenderCommentThreadEmpty(t *testing.T) {
	for name, comments := range map[string][]api.Comment{
		"empty": {},
		"nil":   nil,
	} {
		t.Run(name, func(t *testing.T) {
			out := RenderCommentThread(comments, 80)
			if out == "" {
				t.Fatal("RenderCommentThread(empty) returned an empty string")
			}
			if !strings.Contains(strings.ToLower(mdStripEscape(out)), "no comments") {
				t.Fatalf("RenderCommentThread(empty) = %q, want it to say there are no comments", out)
			}
		})
	}
}

func TestRenderCommentThreadWidths(t *testing.T) {
	comments := []api.Comment{{ID: 1, Body: strings.Repeat("long body ", 200), User: &api.SimpleUser{Login: "octocat"}}}
	for _, width := range []int{0, -1, -200, 1, 20, 40, 80, 200} {
		out := RenderCommentThread(comments, width)
		if out == "" {
			t.Fatalf("RenderCommentThread(width=%d) returned an empty string", width)
		}
		if !strings.Contains(mdStripEscape(out), "octocat") {
			t.Fatalf("RenderCommentThread(width=%d) lost the author", width)
		}
	}
}

func TestRenderCommentThreadCapsLongBody(t *testing.T) {
	comments := []api.Comment{{
		ID:   1,
		Body: strings.Repeat("paragraph\n\n", 500),
		User: &api.SimpleUser{Login: "octocat"},
	}}

	out := RenderCommentThread(comments, 80)
	lines := strings.Split(out, "\n")
	// The box chrome plus the title may add a few lines; the body itself must be
	// clipped rather than dumping 1000+ lines into the terminal.
	if len(lines) > browseMaxCommentLines+browseCommentBoxAllowance() {
		t.Fatalf("thread rendered %d lines for one long comment, want at most %d",
			len(lines), browseMaxCommentLines+browseCommentBoxAllowance())
	}
	if !strings.Contains(mdStripEscape(out), "truncated") {
		t.Fatal("long comment was clipped without telling the reader")
	}
}

// browseCommentBoxAllowance is the slack the surrounding box and header need.
func browseCommentBoxAllowance() int { return 8 }

func TestRenderCommentThreadHandlesOddComments(t *testing.T) {
	// Missing user, empty body and a broken timestamp must not panic.
	comments := []api.Comment{
		{ID: 1},
		{ID: 2, Body: "", User: nil, CreatedAt: "not-a-date"},
		{ID: 3, Body: "body only"},
	}
	out := RenderCommentThread(comments, 60)
	if out == "" {
		t.Fatal("RenderCommentThread() returned an empty string for odd input")
	}
	if !strings.Contains(strings.ToLower(mdStripEscape(out)), "empty reply") {
		t.Fatalf("an empty reply was not labelled as such:\n%s", mdStripEscape(out))
	}
}

func TestBrowseHelpersDoNotPanicOnNil(t *testing.T) {
	var a *api.AdvisoryDetail
	if got := a.Identifier(); got != "" {
		t.Fatalf("nil Identifier() = %q, want an empty string", got)
	}
	if got := browseAdvisoryLabel(nil, 80); got == "" {
		t.Fatal("browseAdvisoryLabel(nil) returned an empty string")
	}
	if got := browseAdvisoryLabel(&api.AdvisoryDetail{}, 0); got == "" {
		t.Fatal("browseAdvisoryLabel(&{}, 0) returned an empty string")
	}
}

func TestBrowseAdvisoryLabelContainsStateSeverityAndSummary(t *testing.T) {
	label := browseAdvisoryLabel(browseFullAdvisory(), 100)
	text := mdStripEscape(label)
	for _, want := range []string{"published", browseSampleGHSA, "high", "Path traversal"} {
		if !strings.Contains(text, want) {
			t.Fatalf("label %q does not contain %q", text, want)
		}
	}
}

func TestBrowseAdvisoryLabelFitsWidth(t *testing.T) {
	a := browseFullAdvisory()
	a.Summary = strings.Repeat("a very long summary ", 40)

	for _, width := range []int{40, 60, 80, 120} {
		label := mdStripEscape(browseAdvisoryLabel(a, width))
		if got := len([]rune(label)); got > width*2 {
			t.Fatalf("label at width %d is %d runes, far wider than expected: %q", width, got, label)
		}
	}
}

func TestBrowseTruncateRunes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{"short stays", "abc", 10, "abc"},
		{"exact stays", "abc", 3, "abc"},
		{"long clipped", "abcdef", 4, "abc…"},
		{"one rune", "abcdef", 1, "…"},
		{"zero budget", "abcdef", 0, ""},
		{"negative budget", "abcdef", -5, ""},
		{"whitespace trimmed", "  abc  ", 10, "abc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := browseTruncateRunes(tc.in, tc.max); got != tc.want {
				t.Fatalf("browseTruncateRunes(%q, %d) = %q, want %q", tc.in, tc.max, got, tc.want)
			}
		})
	}
}

func TestBuildAdvisoryUpdateOnlyChangedFields(t *testing.T) {
	original := browseFullAdvisory()
	baseline := advisoryEditBaseline{
		summary:     strings.TrimSpace(original.Summary),
		description: strings.TrimSpace(original.Description),
		severity:    api.SeverityHigh,
		state:       api.StatePublished,
		cveID:       "CVE-2024-9999",
	}

	t.Run("nothing changed", func(t *testing.T) {
		in := advisoryEditInput{
			Summary:     original.Summary,
			Description: original.Description,
			Severity:    api.SeverityHigh,
			State:       api.StatePublished,
			CVEID:       "CVE-2024-9999",
		}
		patch, changes := buildAdvisoryUpdate(in, baseline)
		if len(changes) != 0 {
			t.Fatalf("changes = %v, want none", changes)
		}
		if !patch.IsEmpty() {
			t.Fatalf("patch = %+v, want an empty patch", patch)
		}
	})

	t.Run("summary only", func(t *testing.T) {
		in := advisoryEditInput{
			Summary:     "A brand new summary",
			Description: original.Description,
			Severity:    api.SeverityHigh,
			State:       api.StatePublished,
			CVEID:       "CVE-2024-9999",
		}
		patch, changes := buildAdvisoryUpdate(in, baseline)
		if patch.Summary == nil || *patch.Summary != "A brand new summary" {
			t.Fatalf("patch.Summary = %v, want the new summary", patch.Summary)
		}
		for _, field := range []string{"Description", "Severity", "State", "CVEID"} {
			switch field {
			case "Description":
				if patch.Description != nil {
					t.Fatalf("patch.Description was set to %q, want nil", *patch.Description)
				}
			case "Severity":
				if patch.Severity != nil {
					t.Fatalf("patch.Severity was set to %q, want nil", *patch.Severity)
				}
			case "State":
				if patch.State != nil {
					t.Fatalf("patch.State was set to %q, want nil", *patch.State)
				}
			case "CVEID":
				if patch.CVEID != nil {
					t.Fatalf("patch.CVEID was set to %q, want nil", *patch.CVEID)
				}
			}
		}
		if len(changes) != 1 || changes[0] != "summary" {
			t.Fatalf("changes = %v, want [summary]", changes)
		}
	})

	t.Run("severity and state", func(t *testing.T) {
		in := advisoryEditInput{
			Summary:     original.Summary,
			Description: original.Description,
			Severity:    api.SeverityLow,
			State:       api.StateClosed,
			CVEID:       "CVE-2024-9999",
		}
		patch, changes := buildAdvisoryUpdate(in, baseline)
		if patch.Severity == nil || *patch.Severity != api.SeverityLow {
			t.Fatalf("patch.Severity = %v, want low", patch.Severity)
		}
		if patch.State == nil || *patch.State != api.StateClosed {
			t.Fatalf("patch.State = %v, want closed", patch.State)
		}
		if patch.Summary != nil || patch.Description != nil || patch.CVEID != nil {
			t.Fatalf("unchanged fields were set: %+v", patch)
		}
		if len(changes) != 2 {
			t.Fatalf("changes = %v, want 2 entries", changes)
		}
	})

	t.Run("clearing the cve id", func(t *testing.T) {
		in := advisoryEditInput{
			Summary:     original.Summary,
			Description: original.Description,
			Severity:    api.SeverityHigh,
			State:       api.StatePublished,
			CVEID:       "   ",
		}
		patch, changes := buildAdvisoryUpdate(in, baseline)
		if patch.CVEID == nil {
			t.Fatal("patch.CVEID = nil, want a pointer to the empty string so the id is cleared")
		}
		if *patch.CVEID != "" {
			t.Fatalf("patch.CVEID = %q, want an empty string", *patch.CVEID)
		}
		if len(changes) != 1 || changes[0] != "cve id" {
			t.Fatalf("changes = %v, want [cve id]", changes)
		}
	})

	t.Run("cve id is case insensitive", func(t *testing.T) {
		in := advisoryEditInput{
			Summary:     original.Summary,
			Description: original.Description,
			Severity:    api.SeverityHigh,
			State:       api.StatePublished,
			CVEID:       "cve-2024-9999",
		}
		patch, _ := buildAdvisoryUpdate(in, baseline)
		if patch.CVEID != nil {
			t.Fatalf("patch.CVEID = %q, want nil (only the casing changed)", *patch.CVEID)
		}
	})
}

func TestBuildAdvisoryUpdateTrimsWhitespace(t *testing.T) {
	baseline := advisoryEditBaseline{
		summary:     "same",
		description: "same",
		severity:    api.SeverityHigh,
		state:       api.StatePublished,
		cveID:       "",
	}
	in := advisoryEditInput{
		Summary:     "  same\n",
		Description: "same  ",
		Severity:    api.SeverityHigh,
		State:       api.StatePublished,
		CVEID:       "",
	}
	patch, changes := buildAdvisoryUpdate(in, baseline)
	if len(changes) != 0 {
		t.Fatalf("changes = %v, want none (only whitespace differed)", changes)
	}
	if !patch.IsEmpty() {
		t.Fatalf("patch = %+v, want an empty patch", patch)
	}
}

func TestNewAdvisoryEditInputPrefills(t *testing.T) {
	in := newAdvisoryEditInput(browseFullAdvisory())
	if in.Summary != browseFullAdvisory().Summary {
		t.Fatalf("Summary = %q, want the advisory's summary", in.Summary)
	}
	if in.Severity != api.SeverityHigh {
		t.Fatalf("Severity = %q, want high", in.Severity)
	}
	if in.State != api.StatePublished {
		t.Fatalf("State = %q, want published", in.State)
	}
	if in.CVEID != "CVE-2024-9999" {
		t.Fatalf("CVEID = %q, want CVE-2024-9999", in.CVEID)
	}
}

func TestNewAdvisoryEditInputTriageFallsBackToEditableState(t *testing.T) {
	a := browseFullAdvisory()
	a.State = string(api.StateTriage)

	in := newAdvisoryEditInput(a)
	if in.State == api.StateTriage {
		t.Fatal("State = triage, but PATCH cannot set triage; want an editable state")
	}
	if !in.State.Editable() {
		t.Fatalf("State = %q, want an editable state", in.State)
	}
}

func TestNewAdvisoryEditInputNil(t *testing.T) {
	in := newAdvisoryEditInput(nil)
	if in.Severity != api.SeverityMedium {
		t.Fatalf("Severity = %q, want the medium default", in.Severity)
	}
	if !in.State.Editable() {
		t.Fatalf("State = %q, want an editable default", in.State)
	}
}

func TestEditableStateOptionsExcludeTriage(t *testing.T) {
	options := editableStateOptions()
	if len(options) == 0 {
		t.Fatal("editableStateOptions() is empty")
	}
	for _, opt := range options {
		if !opt.Value.Editable() {
			t.Fatalf("option %q offers a state PATCH cannot set", opt.Key)
		}
		if opt.Value == api.StateTriage {
			t.Fatal("triage must not be offered")
		}
	}
}

func TestNewAdvisoryEditFormBuilds(t *testing.T) {
	in := newAdvisoryEditInput(browseFullAdvisory())
	if form := newAdvisoryEditForm(&in); form == nil {
		t.Fatal("newAdvisoryEditForm() returned nil")
	}
}

func TestAdvisoryEditFormDoesNotTouchTerminal(t *testing.T) {
	// Building the form must be side-effect free (no TTY needed, no panic) so the
	// editor can be unit-tested on a headless machine.
	in := newAdvisoryEditInput(browseFullAdvisory())
	form := newAdvisoryEditForm(&in)
	if form == nil {
		t.Fatal("newAdvisoryEditForm() returned nil")
	}
	// prepareForm is the shared terminal guard; with no TTY it must supply a
	// fallback size rather than failing.
	if _, err := prepareForm(form); err != nil {
		t.Fatalf("prepareForm(edit form) error = %v", err)
	}
}

func TestBrowseFilterLabel(t *testing.T) {
	cases := map[api.AdvisoryState]string{
		"":                 "all states",
		api.StateDraft:     "Draft",
		api.StateTriage:    "Triage",
		api.StatePublished: "Published",
		api.StateClosed:    "Closed",
	}
	for state, want := range cases {
		if got := browseFilterLabel(state); got != want {
			t.Fatalf("browseFilterLabel(%q) = %q, want %q", state, got, want)
		}
	}
}

func TestBrowseRepoLabel(t *testing.T) {
	cases := []struct {
		owner, repo, want string
	}{
		{"octocat", "hello-world", "octocat/hello-world"},
		{" octocat ", " hello-world ", "octocat/hello-world"},
		{"", "", "(unknown repository)"},
		{"octocat", "", "octocat"},
		{"", "hello-world", "hello-world"},
	}
	for _, tc := range cases {
		if got := browseRepoLabel(tc.owner, tc.repo); got != tc.want {
			t.Fatalf("browseRepoLabel(%q, %q) = %q, want %q", tc.owner, tc.repo, got, tc.want)
		}
	}
}

func TestBrowseNextPageStopsOnLoop(t *testing.T) {
	// A server that keeps pointing at the same page must not spin forever.
	page := api.ListPage[api.AdvisoryDetail]{NextPage: 1, HasMore: true}
	if got := browseNextPage(1, page); got != 0 {
		t.Fatalf("browseNextPage(1, next=1) = %d, want 0 (no progress)", got)
	}
	// HasMore without a page number means "the next one".
	if got := browseNextPage(3, api.ListPage[api.AdvisoryDetail]{HasMore: true}); got != 4 {
		t.Fatalf("browseNextPage(3, hasMore) = %d, want 4", got)
	}
	// A page beyond the hard cap stops the loop.
	if got := browseNextPage(1, api.ListPage[api.AdvisoryDetail]{NextPage: browseMaxPages + 1}); got != 0 {
		t.Fatalf("browseNextPage over the cap = %d, want 0", got)
	}
	// No pagination information means the listing is done.
	if got := browseNextPage(1, api.ListPage[api.AdvisoryDetail]{}); got != 0 {
		t.Fatalf("browseNextPage(no next) = %d, want 0", got)
	}
}

func TestFetchAdvisoriesStopsWhenServerNeverPaginates(t *testing.T) {
	// Page 1 advertises a next page; page 2 returns nothing. The walk must stop,
	// not loop, and must not report an error.
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("page") == "1" {
			w.Header().Set("Link", fmt.Sprintf(`<%s%s?page=2>; rel="next"`, "http://"+r.Host, r.URL.Path))
			fmt.Fprint(w, "["+browseAdvisoryJSON(browseSampleGHSA, "first", "high", "published", "")+"]")
			return
		}
		fmt.Fprint(w, "[]")
	}))
	defer srv.Close()

	client := api.NewClientWithBaseURL("ghp_test", srv.URL)

	advisories, err := FetchAdvisories(context.Background(), client, "octocat", "hello-world", "", 50)
	if err != nil {
		t.Fatalf("FetchAdvisories() error = %v", err)
	}
	if len(advisories) != 1 {
		t.Fatalf("got %d advisories, want 1", len(advisories))
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("server received %d requests, want 2", got)
	}
}

func TestFetchAdvisoriesUsesPerPageLimit(t *testing.T) {
	rec := &browseServerRecords{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record(r)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "[]")
	}))
	defer srv.Close()

	client := api.NewClientWithBaseURL("ghp_test", srv.URL)
	if _, err := FetchAdvisories(context.Background(), client, "octocat", "hello-world", "", 5); err != nil {
		t.Fatalf("FetchAdvisories() error = %v", err)
	}
	queries := rec.queries()
	if len(queries) != 1 {
		t.Fatalf("server received %d requests, want 1", len(queries))
	}
	// The first page only needs `limit` items, so per_page must match that.
	if !strings.Contains(queries[0], "per_page=5") {
		t.Fatalf("query %q does not ask for per_page=5", queries[0])
	}
	if !strings.Contains(queries[0], "page=1") {
		t.Fatalf("query %q does not start at page 1", queries[0])
	}
}

func TestFetchAdvisoriesCapsPerPageAt100(t *testing.T) {
	rec := &browseServerRecords{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record(r)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "[]")
	}))
	defer srv.Close()

	client := api.NewClientWithBaseURL("ghp_test", srv.URL)
	if _, err := FetchAdvisories(context.Background(), client, "octocat", "hello-world", "", 1000); err != nil {
		t.Fatalf("FetchAdvisories() error = %v", err)
	}
	queries := rec.queries()
	if len(queries) != 1 {
		t.Fatalf("server received %d requests, want 1", len(queries))
	}
	if !strings.Contains(queries[0], "per_page=100") {
		t.Fatalf("query %q does not cap per_page at 100", queries[0])
	}
}

func TestFetchHelpersAreNotInteractive(t *testing.T) {
	// Guard against someone wiring runForm into the data path: the helpers must
	// work with no terminal attached (the test binary has none). If a form were
	// reached here it would either block or fail on the missing TTY.
	comments := []api.Comment{{ID: 1, Body: "text", User: &api.SimpleUser{Login: "octocat"}}}
	if got := RenderCommentThread(comments, 80); got == "" {
		t.Fatal("RenderCommentThread() is empty")
	}
	if got := RenderAdvisoryDetail(browseFullAdvisory(), 80); got == "" {
		t.Fatal("RenderAdvisoryDetail() is empty")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "[]")
	}))
	defer srv.Close()

	client := api.NewClientWithBaseURL("ghp_test", srv.URL)
	if _, err := FetchAdvisories(context.Background(), client, "octocat", "hello-world", "", 1); err != nil {
		t.Fatalf("FetchAdvisories() error = %v", err)
	}
	if _, err := FetchComments(context.Background(), client, "octocat", "hello-world", browseSampleGHSA); err != nil {
		t.Fatalf("FetchComments() error = %v", err)
	}
}

func TestBrowseCtxErr(t *testing.T) {
	if err := browseCtxErr(nil); err != nil {
		t.Fatalf("browseCtxErr(nil) = %v, want nil", err)
	}
	if err := browseCtxErr(context.Background()); err != nil {
		t.Fatalf("browseCtxErr(background) = %v, want nil", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := browseCtxErr(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("browseCtxErr(cancelled) = %v, want context.Canceled", err)
	}
}

func TestBrowseInitialCap(t *testing.T) {
	for _, limit := range []int{-10, 0, 1, 20, 50, 51, 10_000} {
		if got := browseInitialCap(limit); got < 0 {
			t.Fatalf("browseInitialCap(%d) = %d, want a non-negative capacity", limit, got)
		}
	}
}

func TestBrowseWidthIsUsable(t *testing.T) {
	width := browseWidth()
	if width < browseMinWidth || width > browseMaxWidth {
		t.Fatalf("browseWidth() = %d, want it within [%d, %d]", width, browseMinWidth, browseMaxWidth)
	}
}

func TestBrowseFilterIncludesEveryStateAndAll(t *testing.T) {
	// The filter picker is built from the same tables the API validates against,
	// so it can never offer a state GitHub would reject.
	for _, state := range api.AdvisoryStates {
		if !state.Valid() {
			t.Fatalf("api.AdvisoryStates contains an invalid state %q", state)
		}
	}
	if browseFilterLabel("") != "all states" {
		t.Fatalf("the empty filter must read as 'all states', got %q", browseFilterLabel(""))
	}
}

func TestBrowseMaxCommentLinesIsSane(t *testing.T) {
	if browseMaxCommentLines <= 0 {
		t.Fatalf("browseMaxCommentLines = %d, want a positive cap", browseMaxCommentLines)
	}
	if browseMaxCommentRunes <= browseMaxCommentLines {
		t.Fatalf("browseMaxCommentRunes = %d must exceed browseMaxCommentLines = %d",
			browseMaxCommentRunes, browseMaxCommentLines)
	}
}

func TestBrowseCommentTitle(t *testing.T) {
	title := mdStripEscape(browseCommentTitle(&api.Comment{
		User:              &api.SimpleUser{Login: "octocat"},
		AuthorAssociation: "MEMBER",
		CreatedAt:         "2024-03-01T00:00:00Z",
	}))
	for _, want := range []string{"@octocat", "member", "2024-03-01"} {
		if !strings.Contains(title, want) {
			t.Fatalf("title %q does not contain %q", title, want)
		}
	}

	// A comment with no author information must still render a title.
	if got := browseCommentTitle(&api.Comment{}); got == "" {
		t.Fatal("browseCommentTitle(&{}) is empty")
	}
}
