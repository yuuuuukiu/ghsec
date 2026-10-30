package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testToken = "ghp_testtoken1234"

// recordedRequest is a snapshot of what the test server received.
type recordedRequest struct {
	method     string
	path       string
	header     http.Header
	body       []byte
	bodyString string
}

// newTestClient starts a test server and returns a client pointed at it plus a
// pointer that is populated with the last request the server saw.
func newTestClient(t *testing.T, status int, responseBody string) (*Client, *recordedRequest) {
	t.Helper()

	rec := &recordedRequest{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		rec.method = r.Method
		rec.path = r.URL.Path
		rec.header = r.Header.Clone()
		rec.body = raw
		rec.bodyString = string(raw)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if responseBody != "" {
			_, _ = io.WriteString(w, responseBody)
		}
	}))
	t.Cleanup(srv.Close)

	return NewClientWithBaseURL(testToken, srv.URL), rec
}

// assertGitHubRequestHeaders verifies the mandatory GitHub request headers.
func assertGitHubRequestHeaders(t *testing.T, h http.Header) {
	t.Helper()

	if got, want := h.Get("Authorization"), "Bearer "+testToken; got != want {
		t.Errorf("Authorization = %q, want %q", got, want)
	}
	if got, want := h.Get("Accept"), "application/vnd.github+json"; got != want {
		t.Errorf("Accept = %q, want %q", got, want)
	}
	if got, want := h.Get("X-GitHub-Api-Version"), "2022-11-28"; got != want {
		t.Errorf("X-GitHub-Api-Version = %q, want %q", got, want)
	}
	if got := strings.TrimSpace(h.Get("User-Agent")); got == "" {
		t.Error("User-Agent header is empty, GitHub requires one")
	}
}

// assertJSONContentType verifies that a body-carrying request is JSON encoded.
func assertJSONContentType(t *testing.T, h http.Header) {
	t.Helper()

	if got, want := h.Get("Content-Type"), "application/json"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}
}

// decodeBody unmarshals a JSON request body into a generic map.
func decodeBody(t *testing.T, raw []byte) map[string]any {
	t.Helper()

	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("request body is not valid JSON (%q): %v", string(raw), err)
	}
	return m
}

const createdAdvisoryJSON = `{
  "ghsa_id": "GHSA-abcd-1234-wxyz",
  "cve_id": "CVE-2024-0001",
  "summary": "Reflected XSS in search",
  "description": "A reflected XSS issue exists in the search box.",
  "severity": "high",
  "state": "triage",
  "html_url": "https://github.com/octocat/hello-world/security/advisories/GHSA-abcd-1234-wxyz",
  "url": "https://api.github.com/repos/octocat/hello-world/security-advisories/GHSA-abcd-1234-wxyz",
  "created_at": "2024-05-01T10:00:00Z"
}`

func TestSubmitPrivateReportHappyPath(t *testing.T) {
	client, rec := newTestClient(t, http.StatusCreated, createdAdvisoryJSON)

	adv, err := client.SubmitPrivateReport(context.Background(), "octocat", "hello-world", PrivateReportRequest{
		Summary:     "Reflected XSS in search",
		Description: "A reflected XSS issue exists in the search box.",
		Severity:    SeverityHigh,
		CVEID:       "CVE-2024-0001",
	})
	if err != nil {
		t.Fatalf("SubmitPrivateReport returned error: %v", err)
	}
	if adv == nil {
		t.Fatal("SubmitPrivateReport returned a nil advisory")
	}
	if adv.GHSAID != "GHSA-abcd-1234-wxyz" {
		t.Errorf("GHSAID = %q, want %q", adv.GHSAID, "GHSA-abcd-1234-wxyz")
	}
	if adv.Severity != "high" {
		t.Errorf("Severity = %q, want %q", adv.Severity, "high")
	}
	if adv.CVEID != "CVE-2024-0001" {
		t.Errorf("CVEID = %q, want %q", adv.CVEID, "CVE-2024-0001")
	}

	if got, want := rec.method, http.MethodPost; got != want {
		t.Errorf("method = %q, want %q", got, want)
	}
	if got, want := rec.path, "/repos/octocat/hello-world/security-advisories/reports"; got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
	assertGitHubRequestHeaders(t, rec.header)
	assertJSONContentType(t, rec.header)

	body := decodeBody(t, rec.body)
	if got, want := body["severity"], "high"; got != want {
		t.Errorf(`body["severity"] = %#v, want %q`, got, want)
	}
	if got, want := body["summary"], "Reflected XSS in search"; got != want {
		t.Errorf(`body["summary"] = %#v, want %q`, got, want)
	}
	if got, want := body["description"], "A reflected XSS issue exists in the search box."; got != want {
		t.Errorf(`body["description"] = %#v, want %q`, got, want)
	}
	if got, want := body["cve_id"], "CVE-2024-0001"; got != want {
		t.Errorf(`body["cve_id"] = %#v, want %q`, got, want)
	}
	if n := strings.Count(rec.bodyString, `"severity"`); n != 1 {
		t.Errorf(`request body mentions "severity" %d times, want exactly 1: %s`, n, rec.bodyString)
	}
}

func TestSubmitPrivateReportOmitsEmptyCVEID(t *testing.T) {
	client, rec := newTestClient(t, http.StatusCreated, createdAdvisoryJSON)

	if _, err := client.SubmitPrivateReport(context.Background(), "octocat", "hello-world", PrivateReportRequest{
		Summary:     "Open redirect",
		Description: "The redirect parameter is not validated.",
		Severity:    SeverityMedium,
	}); err != nil {
		t.Fatalf("SubmitPrivateReport returned error: %v", err)
	}

	body := decodeBody(t, rec.body)
	if _, present := body["cve_id"]; present {
		t.Errorf("body unexpectedly contains cve_id: %s", rec.bodyString)
	}
	if got, want := body["severity"], "medium"; got != want {
		t.Errorf(`body["severity"] = %#v, want %q`, got, want)
	}
}

func TestCreateAdvisoryDraftHappyPath(t *testing.T) {
	client, rec := newTestClient(t, http.StatusCreated, createdAdvisoryJSON)

	adv, err := client.CreateAdvisoryDraft(context.Background(), "octocat", "hello-world", AdvisoryDraftRequest{
		Summary:     "Reflected XSS in search",
		Description: "A reflected XSS issue exists in the search box.",
		Severity:    SeverityCritical,
		CVEID:       "CVE-2024-0002",
	})
	if err != nil {
		t.Fatalf("CreateAdvisoryDraft returned error: %v", err)
	}
	if adv == nil || adv.GHSAID != "GHSA-abcd-1234-wxyz" {
		t.Fatalf("CreateAdvisoryDraft returned unexpected advisory: %#v", adv)
	}

	if got, want := rec.method, http.MethodPost; got != want {
		t.Errorf("method = %q, want %q", got, want)
	}
	if got, want := rec.path, "/repos/octocat/hello-world/security-advisories"; got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
	assertGitHubRequestHeaders(t, rec.header)
	assertJSONContentType(t, rec.header)

	body := decodeBody(t, rec.body)
	if got, want := body["severity"], "critical"; got != want {
		t.Errorf(`body["severity"] = %#v, want %q`, got, want)
	}
	if got, want := body["cve_id"], "CVE-2024-0002"; got != want {
		t.Errorf(`body["cve_id"] = %#v, want %q`, got, want)
	}
	if n := strings.Count(rec.bodyString, `"severity"`); n != 1 {
		t.Errorf(`request body mentions "severity" %d times, want exactly 1: %s`, n, rec.bodyString)
	}
	if _, present := body["affected_text"]; present {
		t.Errorf("affected text must be folded into description, not sent separately: %s", rec.bodyString)
	}
}

func TestCreateAdvisoryDraftMergesAffectedText(t *testing.T) {
	client, rec := newTestClient(t, http.StatusCreated, createdAdvisoryJSON)

	_, err := client.CreateAdvisoryDraft(context.Background(), "octocat", "hello-world", AdvisoryDraftRequest{
		Summary:      "Reflected XSS in search",
		Description:  "A reflected XSS issue exists in the search box.",
		Severity:     SeverityLow,
		AffectedText: "<= 1.2.3",
	})
	if err != nil {
		t.Fatalf("CreateAdvisoryDraft returned error: %v", err)
	}

	body := decodeBody(t, rec.body)
	description, _ := body["description"].(string)
	wantPrefix := "A reflected XSS issue exists in the search box.\n\n## Affected versions\n\n<= 1.2.3"
	if description != wantPrefix {
		t.Errorf("description = %q, want %q", description, wantPrefix)
	}
	if _, present := body["cve_id"]; present {
		t.Errorf("body unexpectedly contains cve_id: %s", rec.bodyString)
	}
}

func TestCreateAdvisoryDraftAffectedOnly(t *testing.T) {
	client, rec := newTestClient(t, http.StatusCreated, createdAdvisoryJSON)

	_, err := client.CreateAdvisoryDraft(context.Background(), "octocat", "hello-world", AdvisoryDraftRequest{
		Summary:      "Reflected XSS in search",
		Severity:     SeverityLow,
		AffectedText: "< 2.0.0",
	})
	if err != nil {
		t.Fatalf("CreateAdvisoryDraft returned error: %v", err)
	}

	body := decodeBody(t, rec.body)
	if got, want := body["description"], "## Affected versions\n\n< 2.0.0"; got != want {
		t.Errorf(`body["description"] = %#v, want %q`, got, want)
	}
}

func TestAdvisoryLocalValidationSkipsNetwork(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, createdAdvisoryJSON)
	}))
	t.Cleanup(srv.Close)
	client := NewClientWithBaseURL(testToken, srv.URL)

	validReport := PrivateReportRequest{Summary: "s", Description: "d", Severity: SeverityHigh}
	validDraft := AdvisoryDraftRequest{Summary: "s", Description: "d", Severity: SeverityHigh}

	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "report: empty summary",
			call: func() error {
				req := validReport
				req.Summary = "   "
				_, err := client.SubmitPrivateReport(context.Background(), "octocat", "hello-world", req)
				return err
			},
		},
		{
			name: "report: empty description",
			call: func() error {
				req := validReport
				req.Description = ""
				_, err := client.SubmitPrivateReport(context.Background(), "octocat", "hello-world", req)
				return err
			},
		},
		{
			name: "report: invalid severity",
			call: func() error {
				req := validReport
				req.Severity = Severity("SEVERE")
				_, err := client.SubmitPrivateReport(context.Background(), "octocat", "hello-world", req)
				return err
			},
		},
		{
			name: "report: empty owner",
			call: func() error {
				_, err := client.SubmitPrivateReport(context.Background(), "", "hello-world", validReport)
				return err
			},
		},
		{
			name: "report: invalid repo spec",
			call: func() error {
				_, err := client.SubmitPrivateReport(context.Background(), "a b", "hello-world", validReport)
				return err
			},
		},
		{
			name: "draft: empty summary",
			call: func() error {
				req := validDraft
				req.Summary = ""
				_, err := client.CreateAdvisoryDraft(context.Background(), "octocat", "hello-world", req)
				return err
			},
		},
		{
			name: "draft: no description and no affected text",
			call: func() error {
				req := validDraft
				req.Description = ""
				_, err := client.CreateAdvisoryDraft(context.Background(), "octocat", "hello-world", req)
				return err
			},
		},
		{
			name: "draft: invalid severity",
			call: func() error {
				req := validDraft
				req.Severity = Severity("nope")
				_, err := client.CreateAdvisoryDraft(context.Background(), "octocat", "hello-world", req)
				return err
			},
		},
		{
			name: "draft: repo spec with slash",
			call: func() error {
				_, err := client.CreateAdvisoryDraft(context.Background(), "octocat", "hello/world", validDraft)
				return err
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if err == nil {
				t.Fatal("expected a validation error, got nil")
			}
			if _, ok := AsAPIError(err); ok {
				t.Fatalf("validation error must not be an *APIError: %v", err)
			}
			var apiErr *APIError
			if errors.As(err, &apiErr) {
				t.Fatalf("validation error wrapped an *APIError: %v", err)
			}
		})
	}

	if hit {
		t.Error("validation failures must not reach the network, but the test server was called")
	}
}

func TestAdvisoryAPIErrorMapping(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		check  func(t *testing.T, err error)
	}{
		{
			name:   "403 forbidden",
			status: http.StatusForbidden,
			body:   `{"message":"Resource not accessible by integration"}`,
			check: func(t *testing.T, err error) {
				t.Helper()
				apiErr, ok := AsAPIError(err)
				if !ok {
					t.Fatalf("expected *APIError, got %T: %v", err, err)
				}
				if !apiErr.IsForbidden() {
					t.Errorf("IsForbidden() = false, want true (status %d)", apiErr.StatusCode)
				}
			},
		},
		{
			name:   "404 not found",
			status: http.StatusNotFound,
			body:   `{"message":"Not Found"}`,
			check: func(t *testing.T, err error) {
				t.Helper()
				apiErr, ok := AsAPIError(err)
				if !ok {
					t.Fatalf("expected *APIError, got %T: %v", err, err)
				}
				if !apiErr.IsNotFound() {
					t.Errorf("IsNotFound() = false, want true (status %d)", apiErr.StatusCode)
				}
			},
		},
		{
			name:   "401 unauthorized",
			status: http.StatusUnauthorized,
			body:   `{"message":"Bad credentials"}`,
			check: func(t *testing.T, err error) {
				t.Helper()
				apiErr, ok := AsAPIError(err)
				if !ok {
					t.Fatalf("expected *APIError, got %T: %v", err, err)
				}
				if !apiErr.IsUnauthorized() {
					t.Errorf("IsUnauthorized() = false, want true (status %d)", apiErr.StatusCode)
				}
			},
		},
		{
			name:   "422 unprocessable",
			status: http.StatusUnprocessableEntity,
			body:   `{"message":"Validation Failed","errors":[{"field":"summary","message":"is too long"}]}`,
			check: func(t *testing.T, err error) {
				t.Helper()
				apiErr, ok := AsAPIError(err)
				if !ok {
					t.Fatalf("expected *APIError, got %T: %v", err, err)
				}
				if apiErr.StatusCode != http.StatusUnprocessableEntity {
					t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, http.StatusUnprocessableEntity)
				}
			},
		},
	}

	req := PrivateReportRequest{Summary: "s", Description: "d", Severity: SeverityHigh}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := newTestClient(t, tc.status, tc.body)
			adv, err := client.SubmitPrivateReport(context.Background(), "octocat", "hello-world", req)
			if err == nil {
				t.Fatalf("expected an error, got advisory %#v", adv)
			}
			if adv != nil {
				t.Errorf("advisory = %#v, want nil on error", adv)
			}
			tc.check(t, err)
		})
	}
}

func TestCreateAdvisoryDraftAPIError(t *testing.T) {
	client, _ := newTestClient(t, http.StatusForbidden, `{"message":"Resource not accessible by integration"}`)

	adv, err := client.CreateAdvisoryDraft(context.Background(), "octocat", "hello-world", AdvisoryDraftRequest{
		Summary:     "s",
		Description: "d",
		Severity:    SeverityHigh,
	})
	if err == nil {
		t.Fatalf("expected an error, got advisory %#v", adv)
	}
	apiErr, ok := AsAPIError(err)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if !apiErr.IsForbidden() {
		t.Errorf("IsForbidden() = false, want true")
	}
}

func TestAdvisoryEmptyBodyOn201(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "empty body", body: ""},
		{name: "whitespace only", body: "   \n"},
		{name: "json null", body: "null"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := newTestClient(t, http.StatusCreated, tc.body)

			adv, err := client.SubmitPrivateReport(context.Background(), "octocat", "hello-world", PrivateReportRequest{
				Summary:     "s",
				Description: "d",
				Severity:    SeverityHigh,
			})
			if err == nil {
				t.Fatalf("expected an error for a %q 201 body, got advisory %#v", tc.body, adv)
			}
			if adv != nil {
				t.Errorf("advisory = %#v, want nil", adv)
			}
		})
	}
}

func TestAdvisoryEscapedRepoPath(t *testing.T) {
	client, rec := newTestClient(t, http.StatusCreated, createdAdvisoryJSON)

	// "safe" characters are used by GitHub repository names; PathEscape must
	// leave them untouched while still routing correctly.
	if _, err := client.SubmitPrivateReport(context.Background(), "my-org", "my.repo_name", PrivateReportRequest{
		Summary:     "s",
		Description: "d",
		Severity:    SeverityHigh,
	}); err != nil {
		t.Fatalf("SubmitPrivateReport returned error: %v", err)
	}

	if got, want := rec.path, "/repos/my-org/my.repo_name/security-advisories/reports"; got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
}
