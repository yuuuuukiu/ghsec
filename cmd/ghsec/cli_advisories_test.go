package main

// Tests for the read/edit/comment commands in cli_advisories.go.
//
// They run the real command functions against a local httptest server, so the
// assertions cover the whole path: flag parsing, validation, credential
// resolution, the api client, and the stdout rendering.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/yukiu/ghsec/internal/api"
)

// testAdvisoryIDs are two well-formed GHSA identifiers used by the fixtures.
var testAdvisoryIDs = []string{"GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"}

// testRepoPath is the API prefix every fixture path starts with.
const testRepoPath = "/repos/acme/widget"

// advisoryFixture is the canned detail object for one advisory.
func advisoryFixture(ghsa string) map[string]any {
	summary := "RCE in the YAML loader"
	return map[string]any{
		"ghsa_id":      ghsa,
		"cve_id":       "CVE-2026-12345",
		"summary":      summary,
		"description":  "Opening a crafted document executes arbitrary code.\n\n## Impact\n\nFull RCE.",
		"severity":     "high",
		"state":        "draft",
		"html_url":     "https://example.test/advisories/" + ghsa,
		"created_at":   "2026-01-02T03:04:05Z",
		"updated_at":   "2026-01-03T03:04:05Z",
		"published_at": "2026-01-04T03:04:05Z",
		"author":       map[string]any{"login": "mona"},
		"cvss":         map[string]any{"score": 8.8, "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"},
		"cwe_ids":      []any{"CWE-502", "CWE-94"},
		"credits":      []any{map[string]any{"login": "octocat", "type": "reporter"}},
		"vulnerabilities": []any{map[string]any{
			"package":                  map[string]any{"ecosystem": "npm", "name": "yaml-loader"},
			"vulnerable_version_range": "<= 1.4.2",
			"patched_versions":         "1.4.3",
		}},
	}
}

// commentFixture is the canned comment object for one comment.
func commentFixture(id int64, login, body string) map[string]any {
	return map[string]any{
		"id":                 id,
		"body":               body,
		"user":               map[string]any{"login": login},
		"author_association": "MEMBER",
		"created_at":         "2026-01-02T03:04:05Z",
		"html_url":           fmt.Sprintf("https://example.test/comments/%d", id),
	}
}

// newAdvisoryServer serves two advisories. It is the helper the other tests use.
func newAdvisoryServer(t *testing.T) (*httptest.Server, *[]recordedCall) {
	t.Helper()
	return newAdvisoryServerN(t, 2)
}

// newAdvisoryServerN serves count advisories through a routing mock:
//
//	GET    /repos/acme/widget/security-advisories          -> array page
//	GET    /repos/acme/widget/security-advisories/GHSA-…   -> full detail
//	PATCH  /repos/acme/widget/security-advisories/GHSA-…   -> merged detail
//	POST   /repos/acme/widget/security-advisories/GHSA-…/cve -> 202, empty body
//	GET    /repos/acme/widget/security-advisories/GHSA-…/comments -> array
//	POST   …/comments                                      -> 201, created comment
//	PATCH  …/comments/{id}                                 -> 200, updated comment
//
// Like GitHub, the list endpoint pages with a Link header. The fixture caps a
// page at two items so that paging can be exercised with a small data set.
func newAdvisoryServerN(t *testing.T, count int) (*httptest.Server, *[]recordedCall) {
	t.Helper()

	var mu sync.Mutex
	calls := make([]recordedCall, 0, 8)

	advisories := make([]map[string]any, 0, count)
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("GHSA-%04d-%04d-%04d", i, i, i)
		advisories = append(advisories, advisoryFixture(id))
	}
	if count >= 1 {
		// Keep the documented fixtures recognisable for the common cases.
		advisories[0] = advisoryFixture(testAdvisoryIDs[0])
	}
	if count >= 2 {
		advisories[1] = advisoryFixture(testAdvisoryIDs[1])
		advisories[1]["cve_id"] = ""
		advisories[1]["summary"] = "Prototype pollution in the option merger"
		advisories[1]["severity"] = "critical"
		advisories[1]["state"] = "published"
	}

	basePath := testRepoPath + "/security-advisories"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		calls = append(calls, recordedCall{
			method: r.Method,
			path:   r.URL.Path,
			header: r.Header.Clone(),
			body:   string(raw),
		})
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		switch {
		case path == basePath && r.Method == http.MethodGet:
			serveAdvisoryPage(w, r, advisories, len(advisories))

		case path == basePath && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"ghsa_id":"`+testAdvisoryIDs[0]+`","state":"draft"}`)

		case strings.HasSuffix(path, "/cve") && r.Method == http.MethodPost:
			// GitHub answers 202 with an empty body: no CVE id is returned.
			w.WriteHeader(http.StatusAccepted)

		case strings.HasSuffix(path, "/comments") && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode([]map[string]any{
				commentFixture(11, "octocat", "Thanks for the report, we are on it."),
				commentFixture(12, "mona", "Fixed in 1.4.3.\nPlease retest."),
			})

		case strings.HasSuffix(path, "/comments") && r.Method == http.MethodPost:
			var payload struct {
				Body string `json:"body"`
			}
			_ = json.Unmarshal(raw, &payload)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(commentFixture(4242, "mona", payload.Body))

		case strings.Contains(path, "/comments/") && r.Method == http.MethodPatch:
			id, _ := strconv.ParseInt(path[strings.LastIndex(path, "/")+1:], 10, 64)
			var payload struct {
				Body string `json:"body"`
			}
			_ = json.Unmarshal(raw, &payload)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(commentFixture(id, "mona", payload.Body))

		case strings.HasPrefix(path, basePath+"/") && r.Method == http.MethodGet:
			ghsa := path[strings.LastIndex(path, "/")+1:]
			detail := advisoryFixture(ghsa)
			// Mirror any overrides the fixtures applied for this id so the
			// detail endpoint agrees with the list endpoint.
			for _, listEntry := range advisories {
				if listEntry["ghsa_id"] == ghsa {
					for _, key := range []string{"cve_id", "summary", "severity", "state"} {
						if v, ok := listEntry[key]; ok {
							detail[key] = v
						}
					}
					break
				}
			}
			_ = json.NewEncoder(w).Encode(detail)

		case strings.HasPrefix(path, basePath+"/") && r.Method == http.MethodPatch:
			ghsa := path[strings.LastIndex(path, "/")+1:]
			detail := advisoryFixture(ghsa)
			var patch map[string]any
			_ = json.Unmarshal(raw, &patch)
			for key, value := range patch {
				detail[key] = value
			}
			_ = json.NewEncoder(w).Encode(detail)

		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"message":"Not Found"}`)
		}
	}))
	t.Cleanup(server.Close)
	return server, &calls
}

// serveAdvisoryPage writes one Link-paged slice of advisories. The fixture caps
// every page at two items, exactly like a server honouring its own maximum.
func serveAdvisoryPage(w http.ResponseWriter, r *http.Request, advisories []map[string]any, total int) {
	const serverPageCap = 2

	page := 1
	if raw := r.URL.Query().Get("page"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			page = n
		}
	}
	perPage := serverPageCap
	if raw := r.URL.Query().Get("per_page"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n < perPage {
			perPage = n
		}
	}

	start := (page - 1) * perPage
	if start > len(advisories) {
		start = len(advisories)
	}
	end := start + perPage
	if end > len(advisories) {
		end = len(advisories)
	}

	if end < total {
		next := page + 1
		w.Header().Set("Link", fmt.Sprintf(
			`<http://example.test%s?page=%d&per_page=%d>; rel="next"`, testRepoPath+"/security-advisories", next, perPage))
	}

	if err := json.NewEncoder(w).Encode(advisories[start:end]); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// runCommand executes fn while capturing stdout/stderr and returns both plus the
// command error.
func runCommand(t *testing.T, ctx context.Context, cmd func(context.Context, []string) error, args []string) (string, string, error) {
	t.Helper()
	var err error
	out, errOut := captureOutput(t, func() { err = cmd(ctx, args) })
	return out, errOut, err
}

// useIsolatedConfig keeps the developer's real profile out of the test.
func useIsolatedConfig(t *testing.T) {
	t.Helper()
	t.Setenv("GHSEC_CONFIG_HOME", t.TempDir())
}

// baseArgs returns the credential/endpoint flags shared by every command.
func baseArgs(serverURL string) []string {
	return []string{"--token", "ghp_test0123456789abcdefghij", "--api-url", serverURL}
}

// mustJSONMap decodes a JSON object, failing the test on malformed input.
func mustJSONMap(t *testing.T, raw string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("not a JSON object: %v\n%q", err, raw)
	}
	return out
}

func TestRunListCmdHumanOutput(t *testing.T) {
	useIsolatedConfig(t)
	server, calls := newAdvisoryServer(t)

	out, _, err := runCommand(t, context.Background(), runListCmd,
		append([]string{"--repo", "acme/widget"}, baseArgs(server.URL)...))
	if err != nil {
		t.Fatalf("runListCmd() = %v", err)
	}

	for _, want := range []string{testAdvisoryIDs[0], testAdvisoryIDs[1], "Published", "High", "-"} {
		if !strings.Contains(out, want) {
			t.Fatalf("list output is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "not assigned") {
		t.Fatalf("list output should render a missing CVE as \"-\":\n%s", out)
	}
	if got := len(*calls); got != 1 {
		t.Fatalf("an unpaged list should take one request, got %d", got)
	}
	if (*calls)[0].method != http.MethodGet || (*calls)[0].path != testRepoPath+"/security-advisories" {
		t.Fatalf("request = %s %s", (*calls)[0].method, (*calls)[0].path)
	}
}

func TestRunListCmdJSONOutput(t *testing.T) {
	useIsolatedConfig(t)
	server, _ := newAdvisoryServer(t)

	out, _, err := runCommand(t, context.Background(), runListCmd,
		append([]string{"--repo", "acme/widget", "--json"}, baseArgs(server.URL)...))
	if err != nil {
		t.Fatalf("runListCmd() = %v", err)
	}

	var got []api.AdvisoryDetail
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("stdout is not a JSON array: %v\n%q", err, out)
	}
	if len(got) != 2 {
		t.Fatalf("advisories = %d, want 2", len(got))
	}
	if got[0].GHSAID != testAdvisoryIDs[0] || got[1].GHSAID != testAdvisoryIDs[1] {
		t.Fatalf("unexpected ids: %q %q", got[0].GHSAID, got[1].GHSAID)
	}
	if got[1].CVEID != "" {
		t.Fatalf("second advisory should have no CVE id, got %q", got[1].CVEID)
	}
}

func TestRunListCmdLimitMakesOneRequest(t *testing.T) {
	useIsolatedConfig(t)
	server, calls := newAdvisoryServer(t)

	out, _, err := runCommand(t, context.Background(), runListCmd,
		append([]string{"--repo", "acme/widget", "--limit", "1"}, baseArgs(server.URL)...))
	if err != nil {
		t.Fatalf("runListCmd() = %v", err)
	}
	if got := len(*calls); got != 1 {
		t.Fatalf("--limit 1 must fetch a single page, got %d requests", got)
	}
	if !strings.Contains(out, testAdvisoryIDs[0]) {
		t.Fatalf("output = %q", out)
	}
	if strings.Contains(out, testAdvisoryIDs[1]) {
		t.Fatalf("--limit 1 must not print the second advisory:\n%s", out)
	}
}

func TestRunListCmdFollowsLinkHeader(t *testing.T) {
	useIsolatedConfig(t)
	server, calls := newAdvisoryServerN(t, 3)

	out, _, err := runCommand(t, context.Background(), runListCmd,
		append([]string{"--repo", "acme/widget", "--limit", "3", "--json"}, baseArgs(server.URL)...))
	if err != nil {
		t.Fatalf("runListCmd() = %v", err)
	}

	var got []api.AdvisoryDetail
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("stdout is not a JSON array: %v\n%q", err, out)
	}
	if len(got) != 3 {
		t.Fatalf("advisories = %d, want 3 (paging must accumulate)", len(got))
	}
	if len(*calls) != 2 {
		t.Fatalf("requests = %d, want 2 (two pages)", len(*calls))
	}
	if (*calls)[1].path != testRepoPath+"/security-advisories" {
		t.Fatalf("second request path = %q", (*calls)[1].path)
	}
}

func TestRunListCmdEmptyResultIsNotAnError(t *testing.T) {
	useIsolatedConfig(t)
	server, _ := newAdvisoryServerN(t, 0)

	out, _, err := runCommand(t, context.Background(), runListCmd,
		append([]string{"--repo", "acme/widget"}, baseArgs(server.URL)...))
	if err != nil {
		t.Fatalf("an empty result must not be an error, got %v", err)
	}
	if !strings.Contains(strings.ToLower(out), "no advisories found") {
		t.Fatalf("output = %q", out)
	}
}

func TestRunListCmdRejectsBadInput(t *testing.T) {
	useIsolatedConfig(t)
	server, calls := newAdvisoryServer(t)

	cases := [][]string{
		{"--repo", "acme/widget", "--state", "bogus"},
		{"--repo", "acme/widget", "--sort", "bogus"},
		{"--repo", "acme/widget", "--limit", "0"},
		{"--repo", "acme/widget", "--limit", "101"},
		{"--repo", "acme/widget", "--page", "0"},
		{"--repo", "noslash"},
		{},
	}
	for _, args := range cases {
		_, _, err := runCommand(t, context.Background(), runListCmd, append(args, baseArgs(server.URL)...))
		if err == nil {
			t.Fatalf("runListCmd(%v) = nil, want a usage error", args)
		}
		if !isUsageError(err) {
			t.Fatalf("runListCmd(%v) error is not a usage error: %v", args, err)
		}
	}
	if got := len(*calls); got != 0 {
		t.Fatalf("invalid input must not reach GitHub, got %d requests", got)
	}
}

func TestRunShowCmdHumanOutput(t *testing.T) {
	useIsolatedConfig(t)
	server, calls := newAdvisoryServer(t)

	out, _, err := runCommand(t, context.Background(), runShowCmd,
		append([]string{"--repo", "acme/widget", "--ghsa", testAdvisoryIDs[0]}, baseArgs(server.URL)...))
	if err != nil {
		t.Fatalf("runShowCmd() = %v", err)
	}

	for _, want := range []string{
		testAdvisoryIDs[0], "CVE-2026-12345", "High", "Draft", "8.8",
		"RCE in the YAML loader", "npm:yaml-loader", "CWE-502", "octocat", "mona",
		"https://example.test/advisories/" + testAdvisoryIDs[0],
		"Opening a crafted document executes arbitrary code.",
		"Full RCE.",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("show output is missing %q:\n%s", want, out)
		}
	}

	if got := len(*calls); got != 1 {
		t.Fatalf("show must not make extra calls, got %d", got)
	}
	if want := testRepoPath + "/security-advisories/" + testAdvisoryIDs[0]; (*calls)[0].path != want {
		t.Fatalf("path = %q, want %q", (*calls)[0].path, want)
	}
}

func TestRunShowCmdSaysWhenNoCVEWasAssigned(t *testing.T) {
	useIsolatedConfig(t)
	server, _ := newAdvisoryServer(t)

	out, _, err := runCommand(t, context.Background(), runShowCmd,
		append([]string{"--repo", "acme/widget", "--ghsa", testAdvisoryIDs[1]}, baseArgs(server.URL)...))
	if err != nil {
		t.Fatalf("runShowCmd() = %v", err)
	}
	if !strings.Contains(out, "not assigned") {
		t.Fatalf("an advisory without a CVE must say so:\n%s", out)
	}
}

func TestRunShowCmdJSONRoundTrip(t *testing.T) {
	useIsolatedConfig(t)
	server, _ := newAdvisoryServer(t)

	out, _, err := runCommand(t, context.Background(), runShowCmd,
		append([]string{"--repo", "acme/widget", "--ghsa", testAdvisoryIDs[0], "--json"}, baseArgs(server.URL)...))
	if err != nil {
		t.Fatalf("runShowCmd() = %v", err)
	}

	var got api.AdvisoryDetail
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("stdout is not a JSON advisory: %v\n%q", err, out)
	}
	if got.GHSAID != testAdvisoryIDs[0] || got.Severity != "high" || got.CVEID != "CVE-2026-12345" {
		t.Fatalf("round-trip lost data: %+v", got)
	}
	if len(got.Vulnerabilities) != 1 || got.Vulnerabilities[0].Package.Name != "yaml-loader" {
		t.Fatalf("vulnerabilities = %+v", got.Vulnerabilities)
	}
}

func TestRenderAdvisoryIsNilSafe(t *testing.T) {
	var buf bytes.Buffer
	if err := renderAdvisory(&buf, nil); err != nil {
		t.Fatalf("renderAdvisory(nil) = %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("renderAdvisory(nil) must still explain the emptiness")
	}

	// An almost-empty advisory must render without panicking on nil sub-fields.
	buf.Reset()
	if err := renderAdvisory(&buf, &api.AdvisoryDetail{}); err != nil {
		t.Fatalf("renderAdvisory(empty) = %v", err)
	}
	if !strings.Contains(buf.String(), "not assigned") {
		t.Fatalf("empty advisory output = %q", buf.String())
	}
}

func TestRenderCommentIsNilSafe(t *testing.T) {
	var buf bytes.Buffer
	if err := renderComment(&buf, nil); err != nil {
		t.Fatalf("renderComment(nil) = %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("renderComment(nil) must still explain the emptiness")
	}

	buf.Reset()
	comment := &api.Comment{ID: 7, Body: "line one\nline two", CreatedAt: "2026-01-02T03:04:05Z",
		AuthorAssociation: "MEMBER", User: &api.SimpleUser{Login: "octocat"}}
	if err := renderComment(&buf, comment); err != nil {
		t.Fatalf("renderComment() = %v", err)
	}
	rendered := buf.String()
	for _, want := range []string{"[2026-01-02T03:04:05Z]", "octocat", "(MEMBER)", "  line one", "  line two"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered comment is missing %q:\n%s", want, rendered)
		}
	}
}

func TestRunCommentsList(t *testing.T) {
	useIsolatedConfig(t)
	server, calls := newAdvisoryServer(t)

	out, _, err := runCommand(t, context.Background(), runCommentsCmd,
		append([]string{"list", "--repo", "acme/widget", "--ghsa", testAdvisoryIDs[0]}, baseArgs(server.URL)...))
	if err != nil {
		t.Fatalf("comments list = %v", err)
	}
	for _, want := range []string{"octocat", "mona", "Thanks for the report", "Fixed in 1.4.3."} {
		if !strings.Contains(out, want) {
			t.Fatalf("comments output is missing %q:\n%s", want, out)
		}
	}
	if got := len(*calls); got != 1 || (*calls)[0].method != http.MethodGet {
		t.Fatalf("calls = %d, first = %+v", got, (*calls)[0])
	}
	if want := testRepoPath + "/security-advisories/" + testAdvisoryIDs[0] + "/comments"; (*calls)[0].path != want {
		t.Fatalf("path = %q, want %q", (*calls)[0].path, want)
	}
}

func TestRunCommentsListJSON(t *testing.T) {
	useIsolatedConfig(t)
	server, _ := newAdvisoryServer(t)

	out, _, err := runCommand(t, context.Background(), runCommentsCmd,
		append([]string{"list", "--repo", "acme/widget", "--ghsa", testAdvisoryIDs[0], "--json"}, baseArgs(server.URL)...))
	if err != nil {
		t.Fatalf("comments list --json = %v", err)
	}

	var got []api.Comment
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("stdout is not a JSON array: %v\n%q", err, out)
	}
	if len(got) != 2 || got[0].AuthorLogin() != "octocat" {
		t.Fatalf("comments = %+v", got)
	}
}

func TestRunCommentsAdd(t *testing.T) {
	useIsolatedConfig(t)
	server, calls := newAdvisoryServer(t)

	out, _, err := runCommand(t, context.Background(), runCommentsCmd,
		append([]string{"add", "--repo", "acme/widget", "--ghsa", testAdvisoryIDs[0], "--body", "hi"}, baseArgs(server.URL)...))
	if err != nil {
		t.Fatalf("comments add = %v", err)
	}

	if got := len(*calls); got != 1 {
		t.Fatalf("calls = %d, want 1", got)
	}
	call := (*calls)[0]
	if call.method != http.MethodPost {
		t.Fatalf("method = %q", call.method)
	}
	if want := testRepoPath + "/security-advisories/" + testAdvisoryIDs[0] + "/comments"; call.path != want {
		t.Fatalf("path = %q, want %q", call.path, want)
	}
	if call.body != `{"body":"hi"}` {
		t.Fatalf("body = %q, want %q", call.body, `{"body":"hi"}`)
	}
	if !strings.Contains(out, "4242") {
		t.Fatalf("output should carry the new comment id: %q", out)
	}
	if !strings.Contains(out, "https://example.test/comments/4242") {
		t.Fatalf("output should carry the new comment url: %q", out)
	}
}

func TestRunCommentsAddRequiresBody(t *testing.T) {
	useIsolatedConfig(t)
	server, calls := newAdvisoryServer(t)

	cases := [][]string{
		{"add", "--repo", "acme/widget", "--ghsa", testAdvisoryIDs[0]},
		{"add", "--repo", "acme/widget", "--ghsa", testAdvisoryIDs[0], "--body", "   "},
		{"add", "--repo", "acme/widget", "--ghsa", testAdvisoryIDs[0], "--body", "x", "--body-file", "y"},
	}
	for _, args := range cases {
		_, _, err := runCommand(t, context.Background(), runCommentsCmd, append(args, baseArgs(server.URL)...))
		if err == nil {
			t.Fatalf("comments %v = nil, want a usage error", args)
		}
		if !isUsageError(err) {
			t.Fatalf("comments %v error is not a usage error: %v", args, err)
		}
	}
	if got := len(*calls); got != 0 {
		t.Fatalf("an invalid body must not be posted, got %d requests", got)
	}
}

func TestRunCommentsAddFromFile(t *testing.T) {
	useIsolatedConfig(t)
	server, calls := newAdvisoryServer(t)

	path := t.TempDir() + "/reply.md"
	if err := writeFileForTest(path, "Thanks, triaged as critical.\n"); err != nil {
		t.Fatal(err)
	}

	_, _, err := runCommand(t, context.Background(), runCommentsCmd,
		append([]string{"add", "--repo", "acme/widget", "--ghsa", testAdvisoryIDs[0], "--body-file", path}, baseArgs(server.URL)...))
	if err != nil {
		t.Fatalf("comments add --body-file = %v", err)
	}
	if got := len(*calls); got != 1 {
		t.Fatalf("calls = %d, want 1", got)
	}
	payload := mustJSONMap(t, (*calls)[0].body)
	if payload["body"] != "Thanks, triaged as critical." {
		t.Fatalf("body = %v", payload["body"])
	}
}

func TestRunCommentsUpdate(t *testing.T) {
	useIsolatedConfig(t)
	server, calls := newAdvisoryServer(t)

	out, _, err := runCommand(t, context.Background(), runCommentsCmd,
		append([]string{"update", "--repo", "acme/widget", "--ghsa", testAdvisoryIDs[0],
			"--comment-id", "5", "--body", "x"}, baseArgs(server.URL)...))
	if err != nil {
		t.Fatalf("comments update = %v", err)
	}

	if got := len(*calls); got != 1 {
		t.Fatalf("calls = %d, want 1", got)
	}
	call := (*calls)[0]
	if call.method != http.MethodPatch {
		t.Fatalf("method = %q, want PATCH", call.method)
	}
	if want := testRepoPath + "/security-advisories/" + testAdvisoryIDs[0] + "/comments/5"; call.path != want {
		t.Fatalf("path = %q, want %q", call.path, want)
	}
	if call.body != `{"body":"x"}` {
		t.Fatalf("body = %q", call.body)
	}
	if !strings.Contains(out, "5") {
		t.Fatalf("output should confirm the comment id: %q", out)
	}
}

func TestRunCommentsCmdUsageErrors(t *testing.T) {
	useIsolatedConfig(t)
	server, calls := newAdvisoryServer(t)

	cases := [][]string{
		{},
		{"bogus"},
		{"list", "--ghsa", testAdvisoryIDs[0]},
		{"list", "--repo", "acme/widget"},
		{"update", "--repo", "acme/widget", "--ghsa", testAdvisoryIDs[0], "--body", "x"},
	}
	for _, args := range cases {
		_, _, err := runCommand(t, context.Background(), runCommentsCmd, append(args, baseArgs(server.URL)...))
		if err == nil {
			t.Fatalf("comments %v = nil, want an error", args)
		}
		if !isUsageError(err) {
			t.Fatalf("comments %v error is not a usage error: %v", args, err)
		}
	}
	if got := len(*calls); got != 0 {
		t.Fatalf("usage errors must not reach GitHub, got %d requests", got)
	}
}

func TestRunCVECmd(t *testing.T) {
	useIsolatedConfig(t)
	server, calls := newAdvisoryServer(t)

	out, _, err := runCommand(t, context.Background(), runCVECmd,
		append([]string{"--repo", "acme/widget", "--ghsa", testAdvisoryIDs[0]}, baseArgs(server.URL)...))
	if err != nil {
		t.Fatalf("runCVECmd() = %v", err)
	}

	if got := len(*calls); got != 1 {
		t.Fatalf("calls = %d, want exactly one", got)
	}
	call := (*calls)[0]
	if call.method != http.MethodPost {
		t.Fatalf("method = %q, want POST", call.method)
	}
	if want := testRepoPath + "/security-advisories/" + testAdvisoryIDs[0] + "/cve"; call.path != want {
		t.Fatalf("path = %q, want %q", call.path, want)
	}
	if !strings.Contains(out, testAdvisoryIDs[0]) {
		t.Fatalf("output should name the advisory: %q", out)
	}
	// The API returns no id, so the command must say the assignment is async.
	if !strings.Contains(strings.ToLower(out), "asynchronous") &&
		!strings.Contains(strings.ToLower(out), "asynchron") {
		t.Fatalf("output must explain the CVE is assigned asynchronously: %q", out)
	}
}

func TestRunCVECmdJSON(t *testing.T) {
	useIsolatedConfig(t)
	server, _ := newAdvisoryServer(t)

	out, _, err := runCommand(t, context.Background(), runCVECmd,
		append([]string{"--repo", "acme/widget", "--ghsa", testAdvisoryIDs[0], "--json"}, baseArgs(server.URL)...))
	if err != nil {
		t.Fatalf("runCVECmd --json = %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%q", err, out)
	}
	if got["ok"] != true || got["requested"] != true {
		t.Fatalf("payload = %v", got)
	}
	if got["ghsa_id"] != testAdvisoryIDs[0] {
		t.Fatalf("ghsa_id = %v", got["ghsa_id"])
	}
}

func TestRunEditCmdOnlySendsTheGivenFields(t *testing.T) {
	useIsolatedConfig(t)
	server, calls := newAdvisoryServer(t)

	out, _, err := runCommand(t, context.Background(), runEditCmd,
		append([]string{"--repo", "acme/widget", "--ghsa", testAdvisoryIDs[0], "--summary", "new"}, baseArgs(server.URL)...))
	if err != nil {
		t.Fatalf("runEditCmd() = %v", err)
	}

	if got := len(*calls); got != 1 {
		t.Fatalf("calls = %d, want 1", got)
	}
	call := (*calls)[0]
	if call.method != http.MethodPatch {
		t.Fatalf("method = %q, want PATCH", call.method)
	}
	if want := testRepoPath + "/security-advisories/" + testAdvisoryIDs[0]; call.path != want {
		t.Fatalf("path = %q, want %q", call.path, want)
	}

	payload := mustJSONMap(t, call.body)
	if payload["summary"] != "new" {
		t.Fatalf("summary = %v", payload["summary"])
	}
	// Pointer semantics: untouched fields must be absent, not sent as "".
	for _, forbidden := range []string{"severity", "state", "description", "cve_id", "cwe_ids", "cvss_vector_string"} {
		if _, ok := payload[forbidden]; ok {
			t.Fatalf("payload must not carry %q, got %s", forbidden, call.body)
		}
	}

	for _, want := range []string{testAdvisoryIDs[0], "Draft", "High"} {
		if !strings.Contains(out, want) {
			t.Fatalf("edit output is missing %q:\n%s", want, out)
		}
	}
}

func TestRunEditCmdClearsCVE(t *testing.T) {
	useIsolatedConfig(t)
	server, calls := newAdvisoryServer(t)

	_, _, err := runCommand(t, context.Background(), runEditCmd,
		append([]string{"--repo", "acme/widget", "--ghsa", testAdvisoryIDs[0], "--cve", ""}, baseArgs(server.URL)...))
	if err != nil {
		t.Fatalf("runEditCmd --cve \"\" = %v", err)
	}

	if got := len(*calls); got != 1 {
		t.Fatalf("calls = %d, want 1", got)
	}
	if !strings.Contains((*calls)[0].body, `"cve_id":""`) {
		t.Fatalf("an empty --cve must clear the field, body = %q", (*calls)[0].body)
	}
}

func TestRunEditCmdStateAndSeverity(t *testing.T) {
	useIsolatedConfig(t)
	server, calls := newAdvisoryServer(t)

	_, _, err := runCommand(t, context.Background(), runEditCmd,
		append([]string{"--repo", "acme/widget", "--ghsa", testAdvisoryIDs[0],
			"--state", "published", "--severity", "critical", "--cwe-ids", "CWE-79,CWE-89"},
			baseArgs(server.URL)...))
	if err != nil {
		t.Fatalf("runEditCmd() = %v", err)
	}

	payload := mustJSONMap(t, (*calls)[0].body)
	if payload["state"] != "published" {
		t.Fatalf("state = %v", payload["state"])
	}
	if payload["severity"] != "critical" {
		t.Fatalf("severity = %v", payload["severity"])
	}
	cwes, ok := payload["cwe_ids"].([]any)
	if !ok || len(cwes) != 2 || cwes[0] != "CWE-79" || cwes[1] != "CWE-89" {
		t.Fatalf("cwe_ids = %v", payload["cwe_ids"])
	}
}

func TestRunEditCmdRejectsTriageState(t *testing.T) {
	useIsolatedConfig(t)
	server, calls := newAdvisoryServer(t)

	_, _, err := runCommand(t, context.Background(), runEditCmd,
		append([]string{"--repo", "acme/widget", "--ghsa", testAdvisoryIDs[0], "--state", "triage"}, baseArgs(server.URL)...))
	if err == nil {
		t.Fatal("--state triage must be rejected client-side")
	}
	if !isUsageError(err) {
		t.Fatalf("error is not a usage error: %v", err)
	}
	if !strings.Contains(err.Error(), "triage") {
		t.Fatalf("error should name the rejected state: %v", err)
	}
	if got := len(*calls); got != 0 {
		t.Fatalf("nothing should be sent, got %d requests", got)
	}
}

func TestRunEditCmdRequiresAMutation(t *testing.T) {
	useIsolatedConfig(t)
	server, calls := newAdvisoryServer(t)

	_, _, err := runCommand(t, context.Background(), runEditCmd,
		append([]string{"--repo", "acme/widget", "--ghsa", testAdvisoryIDs[0]}, baseArgs(server.URL)...))
	if err == nil {
		t.Fatal("an edit without any mutation flag must be a usage error")
	}
	if !isUsageError(err) {
		t.Fatalf("error is not a usage error: %v", err)
	}
	if got := len(*calls); got != 0 {
		t.Fatalf("nothing should be sent, got %d requests", got)
	}
}

func TestRunEditCmdDryRunMakesNoCalls(t *testing.T) {
	useIsolatedConfig(t)
	server, calls := newAdvisoryServer(t)

	out, errOut, err := runCommand(t, context.Background(), runEditCmd,
		append([]string{"--repo", "acme/widget", "--ghsa", testAdvisoryIDs[0],
			"--summary", "new", "--severity", "high", "--dry-run"}, baseArgs(server.URL)...))
	if err != nil {
		t.Fatalf("runEditCmd --dry-run = %v", err)
	}

	if got := len(*calls); got != 0 {
		t.Fatalf("--dry-run must not call GitHub, got %d requests", got)
	}
	if !strings.Contains(errOut, "dry run") {
		t.Fatalf("stderr should note the dry run: %q", errOut)
	}

	// The patch preview must include the fields hidden behind json:"-".
	var preview map[string]any
	if err := json.Unmarshal([]byte(out), &preview); err != nil {
		t.Fatalf("dry-run stdout is not JSON: %v\n%q", err, out)
	}
	if preview["summary"] != "new" || preview["severity"] != "high" {
		t.Fatalf("preview = %v", preview)
	}
	if _, ok := preview["state"]; ok {
		t.Fatalf("preview must only carry the requested fields: %v", preview)
	}
}

func TestAdvisoryCommandsRequireRepoAndGHSA(t *testing.T) {
	useIsolatedConfig(t)
	server, calls := newAdvisoryServer(t)

	commands := map[string]func(context.Context, []string) error{
		"show":    runShowCmd,
		"cve":     runCVECmd,
		"edit":    runEditCmd,
		"list":    runListCmd,
		"cmtList": runCommentsCmd,
	}

	cases := []struct {
		name string
		fn   func(context.Context, []string) error
		args []string
	}{
		{"show/no repo", commands["show"], []string{"--ghsa", testAdvisoryIDs[0]}},
		{"show/no ghsa", commands["show"], []string{"--repo", "acme/widget"}},
		{"show/bad ghsa", commands["show"], []string{"--repo", "acme/widget", "--ghsa", "GHSA-nope"}},
		{"cve/no repo", commands["cve"], []string{"--ghsa", testAdvisoryIDs[0]}},
		{"cve/no ghsa", commands["cve"], []string{"--repo", "acme/widget"}},
		{"edit/no repo", commands["edit"], []string{"--ghsa", testAdvisoryIDs[0], "--summary", "s"}},
		{"edit/no ghsa", commands["edit"], []string{"--repo", "acme/widget", "--summary", "s"}},
		{"list/no repo", commands["list"], []string{"--limit", "1"}},
		{"comments list/no repo", commands["cmtList"], []string{"list", "--ghsa", testAdvisoryIDs[0]}},
		{"comments list/no ghsa", commands["cmtList"], []string{"list", "--repo", "acme/widget"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := runCommand(t, context.Background(), tc.fn, append(tc.args, baseArgs(server.URL)...))
			if err == nil {
				t.Fatal("expected a usage error")
			}
			if !isUsageError(err) {
				t.Fatalf("error is not a usage error: %v", err)
			}
		})
	}
	if got := len(*calls); got != 0 {
		t.Fatalf("no invalid invocation may reach GitHub, got %d requests", got)
	}
}

func TestAdvisoryCommandsSurfaceAPIFailure(t *testing.T) {
	useIsolatedConfig(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"message":"Resource not accessible by integration"}`)
	}))
	t.Cleanup(server.Close)

	out, _, err := runCommand(t, context.Background(), runShowCmd,
		append([]string{"--repo", "acme/widget", "--ghsa", testAdvisoryIDs[0]}, baseArgs(server.URL)...))
	if err == nil {
		t.Fatal("a 403 must fail the command")
	}
	// FriendlyMessage wraps the raw error, so the actionable guidance is present
	// while stdout stays empty.
	if !strings.Contains(err.Error(), "Could not fetch the advisory") {
		t.Fatalf("error = %v", err)
	}
	if strings.TrimSpace(out) != "" {
		t.Fatalf("a failed show must not print data on stdout: %q", out)
	}
	if strings.Contains(err.Error(), "goroutine") {
		t.Fatalf("error leaked internals: %v", err)
	}
}

func TestTruncateRunes(t *testing.T) {
	if got := truncateRunes("short", 10); got != "short" {
		t.Fatalf("truncateRunes(short) = %q", got)
	}
	long := strings.Repeat("é", 10)
	got := truncateRunes(long, 5)
	if len([]rune(got)) != 5 {
		t.Fatalf("truncateRunes() produced %d runes: %q", len([]rune(got)), got)
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("truncated text should end in an ellipsis: %q", got)
	}
}

func TestNormalizeGHSA(t *testing.T) {
	got, err := normalizeGHSA("  ghsa-aaaa-bbbb-cccc ")
	if err != nil {
		t.Fatalf("normalizeGHSA() = %v", err)
	}
	if got != "GHSA-aaaa-bbbb-cccc" {
		t.Fatalf("normalizeGHSA() = %q", got)
	}

	for _, bad := range []string{"", "   ", "GHSA-", "CVE-2026-1234", "GHSA-aaaa-bbbb-cccc/../x"} {
		if _, err := normalizeGHSA(bad); err == nil {
			t.Fatalf("normalizeGHSA(%q) = nil, want an error", bad)
		} else if !isUsageError(err) {
			t.Fatalf("normalizeGHSA(%q) error is not a usage error: %T", bad, err)
		}
	}
}

func TestParseCWEIDs(t *testing.T) {
	got, err := parseCWEIDs(" cwe-79, CWE-89 ,CWE-79")
	if err != nil {
		t.Fatalf("parseCWEIDs() = %v", err)
	}
	if len(got) != 2 || got[0] != "CWE-79" || got[1] != "CWE-89" {
		t.Fatalf("parseCWEIDs() = %v, want deduplicated upper-case ids", got)
	}

	empty, err := parseCWEIDs("")
	if err != nil {
		t.Fatalf("parseCWEIDs(\"\") = %v", err)
	}
	if empty == nil || len(empty) != 0 {
		t.Fatalf("an empty --cwe-ids must clear the list, got %#v", empty)
	}

	for _, bad := range []string{"79", "CWE-", "CWE-79,oops", " , "} {
		if _, err := parseCWEIDs(bad); err == nil {
			t.Fatalf("parseCWEIDs(%q) = nil, want an error", bad)
		}
	}
}

func TestResolveCommentBody(t *testing.T) {
	body, err := resolveCommentBody("  hi  ", "")
	if err != nil || body != "hi" {
		t.Fatalf("resolveCommentBody() = %q, %v", body, err)
	}
	if _, err := resolveCommentBody("hi", "file"); err == nil || !isUsageError(err) {
		t.Fatalf("mutually exclusive sources must be a usage error, got %v", err)
	}
	if _, err := resolveCommentBody("", ""); err == nil || !isUsageError(err) {
		t.Fatalf("a missing body must be a usage error, got %v", err)
	}
	if _, err := resolveCommentBody("", t.TempDir()+"/missing.md"); err == nil {
		t.Fatal("a missing body file must be an error")
	}
}

// writeFileForTest is a tiny helper so the tests do not need a create/open dance
// at every call site.
func writeFileForTest(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
