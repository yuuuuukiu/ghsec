package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is the public GitHub REST API root.
const DefaultBaseURL = "https://api.github.com"

// BaseURLEnv overrides the API root. It follows the same convention as GitHub
// Actions so the tool also works against GitHub Enterprise Server.
const BaseURLEnv = "GITHUB_API_URL"

// BaseURLFromEnv resolves the API root from the environment, falling back to
// the public GitHub API. Blank or schemeless values are ignored so a stray
// variable cannot silently redirect credentials to an unintended host.
func BaseURLFromEnv() string {
	raw := strings.TrimSpace(os.Getenv(BaseURLEnv))
	if raw == "" {
		return DefaultBaseURL
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return DefaultBaseURL
	}
	return strings.TrimRight(raw, "/")
}

// APIVersion is the pinned GitHub REST API version.
const APIVersion = "2022-11-28"

// UserAgent is sent with every request; GitHub requires a UA.
const UserAgent = "ghsec/1.0"

// defaultTimeout bounds a single API call.
const defaultTimeout = 30 * time.Second

// maxResponseSize bounds how much of a response body we will read.
const maxResponseSize = 4 << 20 // 4 MiB

// Client is a minimal GitHub REST client. It is safe for concurrent use.
type Client struct {
	token      string
	baseURL    string
	httpClient *http.Client
	userAgent  string
}

// Option customises a Client.
type Option func(*Client)

// WithBaseURL overrides the API root (used by tests and GitHub Enterprise).
func WithBaseURL(baseURL string) Option {
	return func(c *Client) {
		if baseURL != "" {
			c.baseURL = strings.TrimRight(baseURL, "/")
		}
	}
}

// WithHTTPClient injects a custom HTTP client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		if hc != nil {
			c.httpClient = hc
		}
	}
}

// NewClient builds a client for a personal access token.
//
// The API root comes from $GITHUB_API_URL when set (GitHub Enterprise Server),
// otherwise the public GitHub API is used.
func NewClient(token string) *Client {
	return NewClientWithOptions(token, WithBaseURL(BaseURLFromEnv()))
}

// NewClientWithOptions builds a client with functional options applied.
func NewClientWithOptions(token string, opts ...Option) *Client {
	c := &Client{
		token:     strings.TrimSpace(token),
		baseURL:   DefaultBaseURL,
		userAgent: UserAgent,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: time.Second,
				MaxIdleConns:          10,
				IdleConnTimeout:       60 * time.Second,
			},
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// NewClientWithBaseURL is a convenience constructor primarily used by tests.
func NewClientWithBaseURL(token, baseURL string) *Client {
	return NewClientWithOptions(token, WithBaseURL(baseURL))
}

// BaseURL exposes the configured API root.
func (c *Client) BaseURL() string { return c.baseURL }

// HasToken reports whether the client was given a credential.
func (c *Client) HasToken() bool { return c.token != "" }

// VerifyToken calls GET /user and returns the authenticated account.
func (c *Client) VerifyToken(ctx context.Context) (*User, error) {
	if c.token == "" {
		return nil, &APIError{StatusCode: 401, Message: "no token configured", Method: http.MethodGet, Path: "/user"}
	}
	var user User
	if err := c.do(ctx, http.MethodGet, "/user", nil, &user); err != nil {
		return nil, err
	}
	if user.Login == "" {
		return nil, &APIError{StatusCode: 200, Message: "GitHub returned no login for this token"}
	}
	return &user, nil
}

// do performs a JSON request and decodes a successful response into out.
func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	_, err := c.doWithHeader(ctx, method, path, body, out)
	return err
}

// doWithHeader is do, but also returns the response headers so callers can read
// pagination information from the Link header.
func (c *Client) doWithHeader(ctx context.Context, method, path string, body, out any) (http.Header, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encode request body: %w", err)
		}
		reader = bytes.NewReader(raw)
	}

	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	c.applyHeaders(req)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, wrapTransportError(err, method, path)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.Header, buildAPIError(resp, raw, method, path)
	}

	if out == nil || len(bytes.TrimSpace(raw)) == 0 {
		return resp.Header, nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return resp.Header, &APIError{
			StatusCode: resp.StatusCode,
			Message:    "GitHub returned an unexpected response format",
			Method:     method,
			Path:       path,
			Body:       snippet(raw),
		}
	}
	return resp.Header, nil
}

// nextPageFromHeader parses GitHub's Link header and returns the `rel="next"`
// page number, or 0 when there is no next page.
func nextPageFromHeader(h http.Header) int {
	link := h.Get("Link")
	if link == "" {
		return 0
	}
	for _, part := range strings.Split(link, ",") {
		segments := strings.Split(part, ";")
		if len(segments) < 2 {
			continue
		}
		if !strings.Contains(segments[1], `rel="next"`) {
			continue
		}
		raw := strings.TrimSpace(segments[0])
		raw = strings.TrimPrefix(raw, "<")
		raw = strings.TrimSuffix(raw, ">")
		parsed, err := url.Parse(raw)
		if err != nil {
			continue
		}
		if page := parsed.Query().Get("page"); page != "" {
			if n, err := strconv.Atoi(page); err == nil && n > 0 {
				return n
			}
		}
	}
	return 0
}

// applyHeaders sets authentication and GitHub API negotiation headers.
func (c *Client) applyHeaders(req *http.Request) {
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", APIVersion)
	req.Header.Set("User-Agent", c.userAgent)
}

// buildAPIError converts a non-2xx response into a structured APIError.
func buildAPIError(resp *http.Response, raw []byte, method, path string) *APIError {
	apiErr := &APIError{
		StatusCode: resp.StatusCode,
		Method:     method,
		Path:       path,
		Body:       snippet(raw),
	}

	var payload struct {
		Message string `json:"message"`
		DocURL  string `json:"documentation_url"`
		Errors  []struct {
			Message string `json:"message"`
			Code    string `json:"code"`
			Field   string `json:"field"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(raw, &payload); err == nil {
		apiErr.Message = payload.Message
		apiErr.DocURL = payload.DocURL
		for _, e := range payload.Errors {
			detail := strings.TrimSpace(e.Message)
			if detail == "" {
				continue
			}
			if e.Field != "" {
				detail = e.Field + ": " + detail
			}
			apiErr.Message = strings.TrimSpace(apiErr.Message + " — " + detail)
		}
	}
	if strings.TrimSpace(apiErr.Message) == "" {
		apiErr.Message = resp.Status
	}
	return apiErr
}

// wrapTransportError turns network failures into actionable APIErrors.
func wrapTransportError(err error, method, path string) error {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return &APIError{
			Message: "GitHub did not respond in time; check your network connection and retry",
			Method:  method,
			Path:    path,
		}
	}
	if errors.Is(err, context.Canceled) {
		return &APIError{Message: "request cancelled", Method: method, Path: path}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &APIError{Message: "request timed out", Method: method, Path: path}
	}
	return &APIError{
		Message: "could not reach GitHub: " + err.Error(),
		Method:  method,
		Path:    path,
	}
}

// snippet shortens a raw body for inclusion in error details.
func snippet(raw []byte) string {
	const limit = 300
	text := strings.TrimSpace(string(raw))
	text = strings.Join(strings.Fields(text), " ")
	if len(text) > limit {
		text = text[:limit] + "…"
	}
	return text
}
