package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// strPtr returns a pointer to s, for building patch fields inline.
func strPtr(s string) *string { return &s }

// severityPtr returns a pointer to sev.
func severityPtr(sev Severity) *Severity { return &sev }

// advisoryStatePtr returns a pointer to state.
func advisoryStatePtr(state AdvisoryState) *AdvisoryState { return &state }

// updatedAdvisoryJSON is a realistic PATCH response body.
const updatedAdvisoryJSON = `{
  "ghsa_id": "GHSA-abcd-1234-efgh",
  "cve_id": "CVE-2024-0001",
  "summary": "Reflected XSS in the search box",
  "description": "A reflected XSS issue exists in the search box.",
  "severity": "critical",
  "state": "published",
  "html_url": "https://github.com/octocat/hello-world/security/advisories/GHSA-abcd-1234-efgh",
  "url": "https://api.github.com/repos/octocat/hello-world/security-advisories/GHSA-abcd-1234-efgh",
  "created_at": "2024-05-01T10:00:00Z",
  "updated_at": "2024-05-02T11:00:00Z",
  "published_at": "2024-05-03T12:00:00Z"
}`

func TestUpdateAdvisorySendsOnlyProvidedFields(t *testing.T) {
	client, log := newScriptedClient(t, scriptedResponse{status: http.StatusOK, body: updatedAdvisoryJSON})

	summary := "Reflected XSS in the search box"
	adv, err := client.UpdateAdvisory(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh", AdvisoryUpdatePatch{
		Summary: &summary,
	})
	if err != nil {
		t.Fatalf("UpdateAdvisory returned error: %v", err)
	}

	req := log.last(t)
	if req.method != http.MethodPatch {
		t.Errorf("method = %q, want %q", req.method, http.MethodPatch)
	}
	if want := "/repos/octocat/hello-world/security-advisories/GHSA-abcd-1234-efgh"; req.path != want {
		t.Errorf("path = %q, want %q", req.path, want)
	}
	assertGitHubRequestHeaders(t, req.header)
	assertJSONContentType(t, req.header)

	body := decodeBody(t, req.body)
	if got, want := body["summary"], summary; got != want {
		t.Errorf(`body["summary"] = %#v, want %q`, got, want)
	}
	for _, absent := range []string{"severity", "state", "description", "cve_id", "cwe_ids", "vulnerabilities", "cvss_vector_string", "collaborating_users", "collaborating_teams"} {
		if _, present := body[absent]; present {
			t.Errorf("body unexpectedly contains %q: %s", absent, string(req.body))
		}
	}
	if len(body) != 1 {
		t.Errorf("body has %d keys, want exactly 1: %s", len(body), string(req.body))
	}

	if adv == nil {
		t.Fatal("UpdateAdvisory returned a nil advisory")
	}
	if got, want := adv.GHSAID, "GHSA-abcd-1234-efgh"; got != want {
		t.Errorf("GHSAID = %q, want %q", got, want)
	}
	if got, want := adv.Severity, "critical"; got != want {
		t.Errorf("Severity = %q, want %q (updated value)", got, want)
	}
	if got, want := adv.State, "published"; got != want {
		t.Errorf("State = %q, want %q", got, want)
	}
}

func TestUpdateAdvisoryStateIsSentAsLowercaseWireValue(t *testing.T) {
	client, log := newScriptedClient(t, scriptedResponse{status: http.StatusOK, body: updatedAdvisoryJSON})

	state := StatePublished
	adv, err := client.UpdateAdvisory(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh", AdvisoryUpdatePatch{
		State: &state,
	})
	if err != nil {
		t.Fatalf("UpdateAdvisory returned error: %v", err)
	}
	if adv == nil {
		t.Fatal("UpdateAdvisory returned a nil advisory")
	}

	req := log.last(t)
	body := decodeBody(t, req.body)
	if got, want := body["state"], "published"; got != want {
		t.Errorf(`body["state"] = %#v, want %q`, got, want)
	}
	if len(body) != 1 {
		t.Errorf("body has %d keys, want exactly 1: %s", len(body), string(req.body))
	}
}

func TestUpdateAdvisorySeverityWireValue(t *testing.T) {
	client, log := newScriptedClient(t, scriptedResponse{status: http.StatusOK, body: updatedAdvisoryJSON})

	severity := SeverityCritical
	if _, err := client.UpdateAdvisory(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh", AdvisoryUpdatePatch{
		Severity: &severity,
	}); err != nil {
		t.Fatalf("UpdateAdvisory returned error: %v", err)
	}

	body := decodeBody(t, log.last(t).body)
	if got, want := body["severity"], "critical"; got != want {
		t.Errorf(`body["severity"] = %#v, want %q`, got, want)
	}
}

func TestUpdateAdvisorySendsFullPatchShape(t *testing.T) {
	client, log := newScriptedClient(t, scriptedResponse{status: http.StatusOK, body: updatedAdvisoryJSON})

	summary := "New summary"
	description := "New description"
	cveID := "CVE-2024-12345"
	severity := SeverityHigh
	state := StateClosed
	cweIDs := []string{"CWE-79"}
	vector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"

	if _, err := client.UpdateAdvisory(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh", AdvisoryUpdatePatch{
		Summary:          &summary,
		Description:      &description,
		CVEID:            &cveID,
		Severity:         &severity,
		State:            &state,
		CWEIDs:           &cweIDs,
		CVSSVectorString: &vector,
		Vulnerabilities: []Vulnerability{{
			Package:                Package{Ecosystem: "npm", Name: "hello-world"},
			VulnerableVersionRange: "< 1.2.3",
			PatchedVersions:        "1.2.3",
		}},
		CollaboratingUsers: []string{"helper"},
		CollaboratingTeams: []string{"security"},
	}); err != nil {
		t.Fatalf("UpdateAdvisory returned error: %v", err)
	}

	body := decodeBody(t, log.last(t).body)
	want := map[string]any{
		"summary":             summary,
		"description":         description,
		"cve_id":              cveID,
		"severity":            "high",
		"state":               "closed",
		"cvss_vector_string":  vector,
		"collaborating_users": []any{"helper"},
		"collaborating_teams": []any{"security"},
		"cwe_ids":             []any{"CWE-79"},
	}
	for key, value := range want {
		if got := body[key]; !reflect.DeepEqual(got, value) {
			t.Errorf("body[%q] = %#v, want %#v", key, got, value)
		}
	}
	vulns, ok := body["vulnerabilities"].([]any)
	if !ok || len(vulns) != 1 {
		t.Fatalf(`body["vulnerabilities"] = %#v, want one entry`, body["vulnerabilities"])
	}
	first, ok := vulns[0].(map[string]any)
	if !ok {
		t.Fatalf("vulnerability entry = %#v, want an object", vulns[0])
	}
	if got, wantRange := first["vulnerable_version_range"], "< 1.2.3"; got != wantRange {
		t.Errorf("vulnerable_version_range = %#v, want %q", got, wantRange)
	}
}

func TestUpdateAdvisoryClearsCVEIDWithEmptyString(t *testing.T) {
	client, log := newScriptedClient(t, scriptedResponse{status: http.StatusOK, body: updatedAdvisoryJSON})

	empty := ""
	if _, err := client.UpdateAdvisory(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh", AdvisoryUpdatePatch{
		CVEID: &empty,
	}); err != nil {
		t.Fatalf("UpdateAdvisory returned error: %v", err)
	}

	body := decodeBody(t, log.last(t).body)
	value, present := body["cve_id"]
	if !present {
		t.Fatalf("body does not contain cve_id, so the field cannot be cleared: %s", string(log.last(t).body))
	}
	if got, want := value, ""; got != want {
		t.Errorf(`body["cve_id"] = %#v, want %q`, got, want)
	}
}

func TestUpdateAdvisoryRejectsEmptyPatchWithoutNetwork(t *testing.T) {
	client, log := hitSensingClient(t)

	adv, err := client.UpdateAdvisory(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh", AdvisoryUpdatePatch{})
	if err == nil {
		t.Fatalf("expected an error for an empty patch, got %#v", adv)
	}
	if adv != nil {
		t.Errorf("advisory = %#v, want nil", adv)
	}
	if !strings.Contains(err.Error(), "nothing to update") {
		t.Errorf("error = %q, want it to mention %q", err.Error(), "nothing to update")
	}
	if _, ok := AsAPIError(err); ok {
		t.Errorf("validation error must not be an *APIError: %v", err)
	}
	if got := log.count(); got != 0 {
		t.Errorf("server received %d requests, want 0", got)
	}
}

func TestUpdateAdvisoryRejectsTriageState(t *testing.T) {
	client, log := hitSensingClient(t)

	state := StateTriage
	adv, err := client.UpdateAdvisory(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh", AdvisoryUpdatePatch{
		State: &state,
	})
	if err == nil {
		t.Fatalf("expected an error for the triage state, got %#v", adv)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "triage") {
		t.Errorf("error = %q, want it to explain the triage restriction", err.Error())
	}
	if _, ok := AsAPIError(err); ok {
		t.Errorf("validation error must not be an *APIError: %v", err)
	}
	if got := log.count(); got != 0 {
		t.Errorf("server received %d requests, want 0", got)
	}
}

func TestUpdateAdvisoryRejectsInvalidInputWithoutNetwork(t *testing.T) {
	validSummary := "summary"

	tests := []struct {
		name  string
		owner string
		repo  string
		ghsa  string
		patch AdvisoryUpdatePatch
	}{
		{
			name:  "unknown state",
			owner: "octocat", repo: "hello-world", ghsa: "GHSA-abcd-1234-efgh",
			patch: AdvisoryUpdatePatch{State: advisoryStatePtr(AdvisoryState("archived"))},
		},
		{
			name:  "invalid severity",
			owner: "octocat", repo: "hello-world", ghsa: "GHSA-abcd-1234-efgh",
			patch: AdvisoryUpdatePatch{Severity: severityPtr(Severity("SEVERE"))},
		},
		{
			name:  "invalid cve id",
			owner: "octocat", repo: "hello-world", ghsa: "GHSA-abcd-1234-efgh",
			patch: AdvisoryUpdatePatch{CVEID: strPtr("CVE-2024-1")},
		},
		{
			name:  "malformed ghsa",
			owner: "octocat", repo: "hello-world", ghsa: "GHSA-abc-1234-efgh",
			patch: AdvisoryUpdatePatch{Summary: &validSummary},
		},
		{
			name:  "invalid owner",
			owner: "octo cat", repo: "hello-world", ghsa: "GHSA-abcd-1234-efgh",
			patch: AdvisoryUpdatePatch{Summary: &validSummary},
		},
		{
			name:  "missing repo",
			owner: "octocat", repo: "", ghsa: "GHSA-abcd-1234-efgh",
			patch: AdvisoryUpdatePatch{Summary: &validSummary},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, log := hitSensingClient(t)

			adv, err := client.UpdateAdvisory(context.Background(), tc.owner, tc.repo, tc.ghsa, tc.patch)
			if err == nil {
				t.Fatalf("expected a validation error, got %#v", adv)
			}
			if adv != nil {
				t.Errorf("advisory = %#v, want nil", adv)
			}
			if _, ok := AsAPIError(err); ok {
				t.Fatalf("validation error must not be an *APIError: %v", err)
			}
			if got := log.count(); got != 0 {
				t.Errorf("server received %d requests, want 0: validation must run before the network", got)
			}
		})
	}
}

func TestUpdateAdvisoryAPIError(t *testing.T) {
	client, _ := newScriptedClient(t, scriptedResponse{
		status: http.StatusUnprocessableEntity,
		body:   `{"message":"Validation Failed","errors":[{"field":"summary","message":"is too long"}]}`,
	})

	summary := "s"
	adv, err := client.UpdateAdvisory(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh", AdvisoryUpdatePatch{
		Summary: &summary,
	})
	if err == nil {
		t.Fatalf("expected an error, got %#v", adv)
	}
	if adv != nil {
		t.Errorf("advisory = %#v, want nil", adv)
	}
	apiErr, ok := AsAPIError(err)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, http.StatusUnprocessableEntity)
	}
	if got, want := apiErr.Method, http.MethodPatch; got != want {
		t.Errorf("Method = %q, want %q", got, want)
	}
	if !strings.Contains(apiErr.Message, "summary") {
		t.Errorf("Message = %q, want the field error to be included", apiErr.Message)
	}
}

func TestUpdateAdvisoryEmptyResponseIsError(t *testing.T) {
	client, _ := newScriptedClient(t, scriptedResponse{status: http.StatusOK, body: "null"})

	summary := "s"
	adv, err := client.UpdateAdvisory(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh", AdvisoryUpdatePatch{
		Summary: &summary,
	})
	if err == nil {
		t.Fatalf("expected an error for a null response, got %#v", adv)
	}
	if adv != nil {
		t.Errorf("advisory = %#v, want nil", adv)
	}
	if _, ok := AsAPIError(err); !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
}

func TestRequestCVEAccepted(t *testing.T) {
	client, log := newScriptedClient(t, scriptedResponse{status: http.StatusAccepted, body: ""})

	if err := client.RequestCVE(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh"); err != nil {
		t.Fatalf("RequestCVE returned error for a 202: %v", err)
	}

	req := log.last(t)
	if req.method != http.MethodPost {
		t.Errorf("method = %q, want %q", req.method, http.MethodPost)
	}
	if want := "/repos/octocat/hello-world/security-advisories/GHSA-abcd-1234-efgh/cve"; req.path != want {
		t.Errorf("path = %q, want %q", req.path, want)
	}
	if !strings.HasSuffix(req.path, "/cve") {
		t.Errorf("path = %q, want it to end with /cve", req.path)
	}
	if len(req.body) != 0 {
		t.Errorf("request body = %q, want no body at all", string(req.body))
	}
	if got := req.header.Get("Content-Type"); got != "" {
		t.Errorf("Content-Type = %q, want it unset when there is no body", got)
	}
	assertGitHubRequestHeaders(t, req.header)
}

func TestRequestCVEAcceptsOtherSuccessStatuses(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusCreated, http.StatusAccepted} {
		client, _ := newScriptedClient(t, scriptedResponse{status: status, body: `{"ghsa_id":"GHSA-abcd-1234-efgh"}`})
		if err := client.RequestCVE(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh"); err != nil {
			t.Errorf("status %d: RequestCVE returned error: %v", status, err)
		}
	}
}

func TestRequestCVENotFound(t *testing.T) {
	client, _ := newScriptedClient(t, scriptedResponse{
		status: http.StatusNotFound,
		body:   `{"message":"Not Found"}`,
	})

	err := client.RequestCVE(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh")
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	apiErr, ok := AsAPIError(err)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if !apiErr.IsNotFound() {
		t.Errorf("IsNotFound() = false, want true (status %d)", apiErr.StatusCode)
	}
}

func TestRequestCVEConflictIsAPIError(t *testing.T) {
	client, _ := newScriptedClient(t, scriptedResponse{
		status: http.StatusConflict,
		body:   `{"message":"A CVE has already been requested for this advisory"}`,
	})

	err := client.RequestCVE(context.Background(), "octocat", "hello-world", "GHSA-abcd-1234-efgh")
	if err == nil {
		t.Fatal("expected an error for a 409 response, got nil")
	}
	apiErr, ok := AsAPIError(err)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusConflict {
		t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, http.StatusConflict)
	}
}

func TestRequestCVEValidatesLocally(t *testing.T) {
	tests := []struct {
		name  string
		owner string
		repo  string
		ghsa  string
	}{
		{name: "empty ghsa", owner: "octocat", repo: "hello-world", ghsa: ""},
		{name: "non ghsa id", owner: "octocat", repo: "hello-world", ghsa: "GHSA-abcd-1234"},
		{name: "cve id instead of ghsa", owner: "octocat", repo: "hello-world", ghsa: "CVE-2024-0001"},
		{name: "invalid owner", owner: "", repo: "hello-world", ghsa: "GHSA-abcd-1234-efgh"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, log := hitSensingClient(t)

			err := client.RequestCVE(context.Background(), tc.owner, tc.repo, tc.ghsa)
			if err == nil {
				t.Fatal("expected a validation error, got nil")
			}
			if _, ok := AsAPIError(err); ok {
				t.Fatalf("validation error must not be an *APIError: %v", err)
			}
			if got := log.count(); got != 0 {
				t.Errorf("server received %d requests, want 0: validation must run before the network", got)
			}
		})
	}
}

func TestValidateGHSAID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{name: "canonical", id: "GHSA-abcd-1234-efgh"},
		{name: "upper case groups", id: "GHSA-abcd-1234-efgh"},
		{name: "lower case prefix", id: "ghsa-abcd-1234-efgh"},
		{name: "fully lower case", id: "ghsa-abcd-1234-efgh"},
		{name: "mixed case", id: "GhSa-AbCd-1234-eFgH"},
		{name: "surrounding whitespace", id: "  GHSA-abcd-1234-efgh  "},
		{name: "digits only groups", id: "GHSA-1111-2222-3333"},

		{name: "empty", id: "", wantErr: true},
		{name: "whitespace only", id: "   ", wantErr: true},
		{name: "short final group", id: "GHSA-abc-1234-efgh", wantErr: true},
		{name: "missing final group", id: "GHSA-abcd-1234", wantErr: true},
		{name: "cve id", id: "CVE-2024-1", wantErr: true},
		{name: "wrong prefix", id: "GHSS-abcd-1234-efgh", wantErr: true},
		{name: "no prefix", id: "abcd-1234-efgh", wantErr: true},
		{name: "non alphanumeric group", id: "GHSA-ab/d-1234-efgh", wantErr: true},
		{name: "underscore in group", id: "GHSA-ab_d-1234-efgh", wantErr: true},
		{name: "path traversal", id: "GHSA-../1234-efgh", wantErr: true},
		{name: "too long", id: "GHSA-abcd-1234-efghi", wantErr: true},
		{name: "too many groups", id: "GHSA-abcd-1234-efgh-ijkl", wantErr: true},
		{name: "spaces inside", id: "GHSA abcd 1234 efgh", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateGHSAID(tc.id)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ValidateGHSAID(%q) = nil, want an error", tc.id)
				}
				if _, ok := AsAPIError(err); ok {
					t.Fatalf("validation error must not be an *APIError: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateGHSAID(%q) returned error: %v", tc.id, err)
			}
		})
	}
}

// TestNormalizeGHSAIDCanonicalCasing pins the canonical form: an upper-case
// "GHSA-" prefix with a lower-case suffix, which is what GitHub itself returns
// (for example GHSA-qr28-fpjm-wq7f). The API resolves ids case-insensitively,
// but storing or displaying the canonical form keeps the tool consistent with
// GitHub's own output.
func TestNormalizeGHSAIDCanonicalCasing(t *testing.T) {
	for _, id := range []string{"ghsa-abcd-1234-efgh", "GHSA-abcd-1234-efgh", "GhSa-ABCD-1234-EfGh"} {
		got, err := normalizeGHSAID(id)
		if err != nil {
			t.Fatalf("normalizeGHSAID(%q) returned error: %v", id, err)
		}
		if want := "GHSA-abcd-1234-efgh"; got != want {
			t.Errorf("normalizeGHSAID(%q) = %q, want %q", id, got, want)
		}
	}
}

func TestValidateCVEID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{name: "empty means no cve", id: ""},
		{name: "whitespace means no cve", id: "   "},
		{name: "canonical", id: "CVE-2024-1234"},
		{name: "five digit sequence", id: "CVE-2024-12345"},
		{name: "long sequence", id: "CVE-2024-1234567"},
		{name: "lower case prefix", id: "cve-2024-1234"},
		{name: "surrounding whitespace", id: " CVE-2024-1234 "},

		{name: "too few sequence digits", id: "CVE-2024-1", wantErr: true},
		{name: "three sequence digits", id: "CVE-2024-123", wantErr: true},
		{name: "missing sequence", id: "CVE-2024", wantErr: true},
		{name: "short year", id: "CVE-24-1234", wantErr: true},
		{name: "long year", id: "CVE-20245-1234", wantErr: true},
		{name: "non numeric year", id: "CVE-abcd-1234", wantErr: true},
		{name: "non numeric sequence", id: "CVE-2024-12ab", wantErr: true},
		{name: "wrong prefix", id: "CWE-2024-1234", wantErr: true},
		{name: "ghsa id", id: "GHSA-abcd-1234-efgh", wantErr: true},
		{name: "extra group", id: "CVE-2024-1234-1", wantErr: true},
		{name: "leading dash in sequence", id: "CVE-2024--1234", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateCVEID(tc.id)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ValidateCVEID(%q) = nil, want an error", tc.id)
				}
				if _, ok := AsAPIError(err); ok {
					t.Fatalf("validation error must not be an *APIError: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateCVEID(%q) returned error: %v", tc.id, err)
			}
		})
	}
}

func TestUpdateAdvisoryPatchJSONOmitsUnsetFields(t *testing.T) {
	// A direct check of the shared wire conversion, so a regression in
	// advisory_models.go's toWire is caught from the write path's point of view.
	summary := "only a summary"
	raw, err := json.Marshal(AdvisoryUpdatePatch{Summary: &summary}.toWire())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "severity") || strings.Contains(string(raw), "state") {
		t.Errorf("wire body leaked unset fields: %s", string(raw))
	}
	if !strings.Contains(string(raw), `"summary":"only a summary"`) {
		t.Errorf("wire body lost the summary: %s", string(raw))
	}
}

func TestValidationErrorsAreNotAPIErrors(t *testing.T) {
	err := ValidateGHSAID("nope")
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		t.Fatalf("ValidateGHSAID error unwraps to *APIError: %v", err)
	}
	if err := ValidateCVEID("nope"); errors.As(err, &apiErr) {
		t.Fatalf("ValidateCVEID error unwraps to *APIError: %v", err)
	}
}
