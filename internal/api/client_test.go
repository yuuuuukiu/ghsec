package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewClientDefaults(t *testing.T) {
	c := NewClient("  ghp_abc  ")
	if !c.HasToken() {
		t.Fatal("HasToken() = false, want true")
	}
	if got := c.BaseURL(); got != DefaultBaseURL {
		t.Fatalf("BaseURL() = %q, want %q", got, DefaultBaseURL)
	}
	if NewClient("").HasToken() {
		t.Fatal("HasToken() = true for an empty token")
	}
}

func TestVerifyTokenSuccess(t *testing.T) {
	var gotPath, gotAuth, gotAccept, gotVersion, gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotAccept = r.Header.Get("Accept")
		gotVersion = r.Header.Get("X-GitHub-Api-Version")
		gotUA = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"login":"octocat","id":1,"name":"The Octocat","html_url":"https://github.com/octocat"}`))
	}))
	defer srv.Close()

	c := NewClientWithBaseURL("ghp_testtoken", srv.URL)
	user, err := c.VerifyToken(context.Background())
	if err != nil {
		t.Fatalf("VerifyToken() error = %v", err)
	}
	if user.Login != "octocat" {
		t.Fatalf("Login = %q, want octocat", user.Login)
	}
	if gotPath != "/user" {
		t.Fatalf("path = %q, want /user", gotPath)
	}
	if gotAuth != "Bearer ghp_testtoken" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if gotAccept != "application/vnd.github+json" {
		t.Fatalf("Accept = %q", gotAccept)
	}
	if gotVersion != APIVersion {
		t.Fatalf("X-GitHub-Api-Version = %q, want %q", gotVersion, APIVersion)
	}
	if strings.TrimSpace(gotUA) == "" {
		t.Fatal("User-Agent must be set")
	}
}

func TestVerifyTokenNoTokenSkipsNetwork(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
	}))
	defer srv.Close()

	c := NewClientWithBaseURL("", srv.URL)
	if _, err := c.VerifyToken(context.Background()); err == nil {
		t.Fatal("VerifyToken() must fail without a token")
	}
	if hit {
		t.Fatal("VerifyToken() must not perform a request without a token")
	}
}

func TestVerifyTokenMissingLoginIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := NewClientWithBaseURL("ghp_x", srv.URL)
	if _, err := c.VerifyToken(context.Background()); err == nil {
		t.Fatal("VerifyToken() must fail when login is absent")
	}
}

func TestVerifyTokenUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Bad credentials","documentation_url":"https://docs.github.com"}`))
	}))
	defer srv.Close()

	c := NewClientWithBaseURL("ghp_bad", srv.URL)
	_, err := c.VerifyToken(context.Background())
	if err == nil {
		t.Fatal("VerifyToken() must fail on 401")
	}
	apiErr, ok := AsAPIError(err)
	if !ok {
		t.Fatalf("error is not *APIError: %T", err)
	}
	if !apiErr.IsUnauthorized() {
		t.Fatalf("IsUnauthorized() = false (status %d)", apiErr.StatusCode)
	}
	if apiErr.Message != "Bad credentials" {
		t.Fatalf("Message = %q", apiErr.Message)
	}
	if apiErr.DocURL == "" {
		t.Fatal("DocURL must be captured")
	}
}

func TestVerifyTokenMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{not json`))
	}))
	defer srv.Close()

	c := NewClientWithBaseURL("ghp_x", srv.URL)
	_, err := c.VerifyToken(context.Background())
	if err == nil {
		t.Fatal("VerifyToken() must fail on malformed JSON")
	}
	if _, ok := AsAPIError(err); !ok {
		t.Fatalf("error is not *APIError: %T", err)
	}
}

func TestVerifyTokenContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte(`{"login":"octocat"}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := NewClientWithBaseURL("ghp_x", srv.URL)
	if _, err := c.VerifyToken(ctx); err == nil {
		t.Fatal("VerifyToken() must fail when the context is cancelled")
	}
}

func TestVerifyTokenUnreachableHost(t *testing.T) {
	c := NewClientWithBaseURL("ghp_x", "http://127.0.0.1:9")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := c.VerifyToken(ctx)
	if err == nil {
		t.Fatal("VerifyToken() must fail when the host is unreachable")
	}
	apiErr, ok := AsAPIError(err)
	if !ok {
		t.Fatalf("error is not *APIError: %T", err)
	}
	if apiErr.StatusCode != 0 {
		t.Fatalf("StatusCode = %d, want 0 for transport errors", apiErr.StatusCode)
	}
}

func TestErrorHelpers(t *testing.T) {
	if (*APIError)(nil).Error() == "" {
		t.Fatal("nil APIError must still produce a message")
	}
	var nilErr *APIError
	if nilErr.IsForbidden() || nilErr.IsNotFound() || nilErr.IsUnauthorized() || nilErr.IsRateLimited() {
		t.Fatal("nil APIError predicates must be false")
	}

	cases := []struct {
		name string
		err  *APIError
		ceh  func(*APIError) bool
	}{
		{"403", &APIError{StatusCode: 403}, (*APIError).IsForbidden},
		{"404", &APIError{StatusCode: 404}, (*APIError).IsNotFound},
		{"401", &APIError{StatusCode: 401}, (*APIError).IsUnauthorized},
	}
	for _, tc := range cases {
		if !tc.ceh(tc.err) {
			t.Fatalf("%s predicate returned false", tc.name)
		}
	}

	limited := &APIError{StatusCode: 403, Message: "API rate limit exceeded"}
	if !limited.IsRateLimited() {
		t.Fatal("IsRateLimited() = false for a rate-limit 403")
	}
	if (&APIError{StatusCode: 404}).IsRateLimited() {
		t.Fatal("IsRateLimited() = true for a 404")
	}
}

func TestFriendlyMessage(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"401", &APIError{StatusCode: 401}, "expired"},
		{"403 permission", &APIError{StatusCode: 403}, "private vulnerability reporting"},
		{"403 rate limit", &APIError{StatusCode: 403, Message: "API rate limit exceeded"}, "rate limit"},
		{"404", &APIError{StatusCode: 404}, "not found"},
		{"422", &APIError{StatusCode: 422}, "rejected the submitted data"},
		{"500", &APIError{StatusCode: 500}, "retry"},
		{"transport", &APIError{Message: "could not reach GitHub"}, "could not reach GitHub"},
		{"plain", context.Canceled, "context canceled"},
	}
	for _, tc := range cases {
		got := FriendlyMessage(tc.err, "submit the report")
		if !strings.Contains(got, tc.want) {
			t.Fatalf("%s: FriendlyMessage() = %q, want it to contain %q", tc.name, got, tc.want)
		}
		if strings.Contains(got, "{") {
			t.Fatalf("%s: FriendlyMessage() leaked raw JSON: %q", tc.name, got)
		}
	}
	if got := FriendlyMessage(nil, "x"); got != "" {
		t.Fatalf("FriendlyMessage(nil) = %q, want empty", got)
	}
	// Default action must not render an empty "Could not :" message.
	if got := FriendlyMessage(&APIError{StatusCode: 418}, ""); !strings.Contains(got, "complete the request") {
		t.Fatalf("default action message = %q", got)
	}
}

func TestSeverityHelpers(t *testing.T) {
	for _, s := range SeverityLevels {
		if !s.Valid() {
			t.Fatalf("%q must be valid", s)
		}
		if SeverityLabel(s) == "Unknown" {
			t.Fatalf("SeverityLabel(%q) = Unknown", s)
		}
	}
	if Severity("bogus").Valid() {
		t.Fatal("bogus severity must be invalid")
	}
	if SeverityLabel(Severity("bogus")) != "Unknown" {
		t.Fatal("SeverityLabel must fall back to Unknown")
	}

	sev, err := ParseSeverity("  HIGH ")
	if err != nil || sev != SeverityHigh {
		t.Fatalf("ParseSeverity() = %q, %v", sev, err)
	}
	if _, err := ParseSeverity("severe"); err == nil {
		t.Fatal("ParseSeverity must reject unknown values")
	}
	if got := SeverityLabel(SeverityHigh); got != "High" {
		t.Fatalf("SeverityLabel(high) = %q", got)
	}
}

func TestAdvisoryIdentifier(t *testing.T) {
	if got := (*Advisory)(nil).Identifier(); got != "" {
		t.Fatalf("nil Identifier() = %q", got)
	}
	if got := (&Advisory{GHSAID: "GHSA-1234"}).Identifier(); got != "GHSA-1234" {
		t.Fatalf("Identifier() = %q", got)
	}
	if got := (&Advisory{CVEID: "CVE-2024-1"}).Identifier(); got != "CVE-2024-1" {
		t.Fatalf("Identifier() = %q", got)
	}
	if got := (&Advisory{}).Identifier(); got != "(unknown id)" {
		t.Fatalf("Identifier() = %q", got)
	}
}

func TestBaseURLFromEnv(t *testing.T) {
	cases := []struct {
		name string
		env  string
		want string
	}{
		{"unset", "", DefaultBaseURL},
		{"blank", "   ", DefaultBaseURL},
		{"enterprise", "https://github.example.com/api/v3", "https://github.example.com/api/v3"},
		{"trailing slash", "https://github.example.com/api/v3/", "https://github.example.com/api/v3"},
		{"localhost http", "http://127.0.0.1:8080", "http://127.0.0.1:8080"},
		// A bare host or an unsupported scheme must not silently redirect tokens.
		{"no scheme", "github.evil.example.com", DefaultBaseURL},
		{"ftp scheme", "ftp://example.com", DefaultBaseURL},
		{"garbage", "://nonsense", DefaultBaseURL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(BaseURLEnv, tc.env)
			if got := BaseURLFromEnv(); got != tc.want {
				t.Fatalf("BaseURLFromEnv() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNewClientHonoursBaseURLEnv(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte(`{"login":"enterprise-user"}`))
	}))
	defer srv.Close()

	t.Setenv(BaseURLEnv, srv.URL)
	user, err := NewClient("ghp_enterprise").VerifyToken(context.Background())
	if err != nil {
		t.Fatalf("VerifyToken() error = %v", err)
	}
	if user.Login != "enterprise-user" {
		t.Fatalf("Login = %q", user.Login)
	}
	if hits != 1 {
		t.Fatalf("server hits = %d, want 1", hits)
	}

	// WithBaseURL must still win over the environment.
	t.Setenv(BaseURLEnv, "https://wrong.example.com")
	c := NewClientWithOptions("ghp_x", WithBaseURL(srv.URL))
	if c.BaseURL() != srv.URL {
		t.Fatalf("BaseURL() = %q, want %q", c.BaseURL(), srv.URL)
	}
}

func TestNextPageFromHeader(t *testing.T) {
	cases := []struct {
		name string
		link string
		want int
	}{
		{"empty", "", 0},
		{
			"next only",
			`<https://api.github.com/advisories?per_page=2&page=3>; rel="next"`,
			3,
		},
		{
			"prev and next",
			`<https://api.github.com/x?page=1>; rel="prev", <https://api.github.com/x?page=3>; rel="next"`,
			3,
		},
		{
			"last page has no next",
			`<https://api.github.com/x?page=1>; rel="prev", <https://api.github.com/x?page=1>; rel="first"`,
			0,
		},
		{"malformed", `not a link header`, 0},
		{"cursor style next has no page", `<https://api.github.com/x?after=abc>; rel="next"`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.link != "" {
				h.Set("Link", tc.link)
			}
			if got := nextPageFromHeader(h); got != tc.want {
				t.Fatalf("nextPageFromHeader() = %d, want %d", got, tc.want)
			}
		})
	}
}
