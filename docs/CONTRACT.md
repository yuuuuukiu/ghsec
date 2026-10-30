# ghsec — Shared Package Contract (read before writing code)

Module: `github.com/yuuuuukiu/ghsec`   Go 1.24.3
TUI stack: huh v1.0.0, lipgloss v1.1.1-0.20250404203927-76690c660834, glamour v1.0.0

## File ownership (DO NOT edit files outside your scope)

| Owner | Files |
|---|---|
| lead | `internal/config/**`, `internal/api/types.go`, `internal/api/client.go`, `internal/tui/theme.go`, `cmd/ghsec/main.go`, `Makefile`, `README.md` |
| api-svc | `internal/api/advisories.go`, `internal/api/repo.go`, `internal/api/*_test.go` (except config/client tests) |
| editor-views | `internal/editor/**`, `internal/tui/views.go` |
| tui-flows | `internal/tui/forms.go`, `internal/tui/menu.go` |

## internal/config (implemented by lead — already on disk)

```go
type Profile struct {
    Token    string `json:"token"`
    Username string `json:"username"`
}
type Config struct {
    ActiveProfile string             `json:"active_profile"`
    Profiles      map[string]Profile `json:"profiles"` // key = alias
}

func Dir() (string, error)
func Path() (string, error)
func Load() (*Config, error)                 // missing file => empty config + ErrNoConfig
func LoadFrom(path string) (*Config, error)  // test seam
func (c *Config) Save() error                // atomic, file 0600, dir 0700
func (c *Config) SaveTo(path string) error
func (c *Config) IsEmpty() bool
func (c *Config) Active() (alias string, p Profile, ok bool)
func (c *Config) SetActive(alias string) error
func (c *Config) AddProfile(alias string, p Profile) error
func (c *Config) RemoveProfile(alias string) error   // refuses to remove last profile
func (c *Config) Aliases() []string                  // sorted
func MaskToken(token string) string                  // "ghp_****1234"
func ValidateAlias(alias string) error               // ^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$
var ErrNoConfig = errors.New(...)
```

## internal/api (types + client by lead; advisories by api-svc)

```go
type Client struct{ /* ... */ }
func NewClient(token string) *Client
func NewClientWithBaseURL(token, baseURL string) *Client // test seam

type User struct {
    Login string `json:"login"`
    ID    int64  `json:"id"`
    Name  string `json:"name"`
    HTMLURL string `json:"html_url"`
}
func (c *Client) VerifyToken(ctx context.Context) (*User, error)

type Severity string
const (
    SeverityCritical Severity = "critical"
    SeverityHigh     Severity = "high"
    SeverityMedium   Severity = "medium"
    SeverityLow      Severity = "low"
)
func (s Severity) Valid() bool
func ParseSeverity(s string) (Severity, error)
func SeverityLabel(s Severity) string

type Advisory struct {
    GHSAID      string   `json:"ghsa_id"`
    CVEID       string   `json:"cve_id"`
    Summary     string   `json:"summary"`
    Description string   `json:"description"`
    Severity    string   `json:"severity"`
    State       string   `json:"state"`
    HTMLURL     string   `json:"html_url"`
    APIURL      string   `json:"url"`
    PublishedAt string   `json:"published_at"`
    CreatedAt   string   `json:"created_at"`
}

type PrivateReportRequest struct {
    Summary     string   `json:"summary"`
    Description string   `json:"description"`
    Severity    Severity `json:"-"`
    CVEID       string   `json:"cve_id,omitempty"`
}
type AdvisoryDraftRequest struct {
    Summary       string   `json:"summary"`
    Description   string   `json:"description"`
    Severity      Severity `json:"-"`
    CVEID         string   `json:"cve_id,omitempty"`
    AffectedText  string   `json:"-"`
}

// api-svc implements these three:
func (c *Client) SubmitPrivateReport(ctx context.Context, owner, repo string, req PrivateReportRequest) (*Advisory, error)
func (c *Client) CreateAdvisoryDraft(ctx context.Context, owner, repo string, req AdvisoryDraftRequest) (*Advisory, error)
func (c *Client) GetRepository(ctx context.Context, owner, repo string) (*Repository, error)
type Repository struct { FullName, HTMLURL string; Private bool; AdvisoryEnabled bool }

// Errors (defined in types.go by lead)
type APIError struct {
    StatusCode int
    Message    string
    DocURL     string
    Method     string
    Path       string
    Body       string
}
func (e *APIError) Error() string
func AsAPIError(err error) (*APIError, bool)
func (e *APIError) IsForbidden() bool  // 403
func (e *APIError) IsNotFound() bool   // 404
func (e *APIError) IsUnauthorized() bool // 401
func FriendlyMessage(err error, action string) string  // user-facing, no panics, no raw logs
func ValidateRepoSpec(spec string) (owner, repo string, err error) // "owner/repo"
```

Endpoint constants (api-svc): base `https://api.github.com`, headers
`Authorization: Bearer <token>`, `Accept: application/vnd.github+json`,
`X-GitHub-Api-Version: 2022-11-28`, `User-Agent: ghsec/<version>`.

- `POST /repos/{owner}/{repo}/security-advisories/reports`  → 201
- `POST /repos/{owner}/{repo}/security-advisories`          → 201
- `GET  /repos/{owner}/{repo}`                              → 200

## internal/editor (editor-views)

```go
func ResolveEditor() Editor                       // $VISUAL > $EDITOR > nano/vim/notepad
type Editor struct{ Name string; Args []string; Source string }
func Open(initial string) (string, error)         // temp file (0600), stdio attached, returns new content
func ReadFile(path string) (string, error)        // ~ expansion, dir/size guards, 4MB cap
func ReadMultiline(in io.Reader, out io.Writer, prompt string) (string, error) // ends on blank line or lone "."
```

## internal/tui (theme by lead, rest split)

```go
// theme.go — DONE by lead
func Theme() *huh.Theme
func Banner() string
func SuccessPanel(title, body string) string
func ErrorPanel(title, body string) string
func WarnPanel(title, body string) string
func InfoPanel(title, body string) string
func Header(text string) string
func KeyValue(label, value string) string
func Muted(s string) string
func Badge(text string) string
func SeverityBadge(sev api.Severity) string
func Dim(s string) string
func Box(title, body string, border lipgloss.Color) string

// views.go — editor-views
func RenderMarkdown(md string, width int) string       // glamour, safe fallback to raw text
func PreviewPanel(title, markdown string, width int) string // glamour inside lipgloss box
func SuccessCard(a *api.Advisory) string
func WelcomeCard(alias, username string) string

// forms.go + menu.go — tui-flows
type ReportInput struct {
    Repo, Summary, Description, CVEID string
    Severity api.Severity
}
type AdvisorInput struct {
    Repo, Summary, Description, CVEID, Affected string
    Severity api.Severity
}
type ProfileInput struct { Token, Alias string }

func RunMainMenu(alias, username string) (Action, error)
func RunOnboarding() (*ProfileInput, error)
func RunPrivateReportForm(defaultRepo string) (*ReportInput, error)
func RunAdvisoryForm(defaultRepo string) (*AdvisorInput, error)
func RunProfileMenu(aliases []string, active string) (ProfAction, error)
func RunTokenPrompt() (*ProfileInput, error)
func RunDescriptionSource() (Source, error)
func RunConfirm(prompt string, def bool) (bool, error)
func RunTextInput(title, desc, placeholder string, validate func(string) error) (string, error)
func RunNote(title, body string) error
type Action int; const (ActionReport, ActionAdvisory, ActionProfiles, ActionQuit)
type ProfAction int; const (ProfSwitch, ProfAdd, ProfDelete, ProfBack)
type Source int; const (SourceFile, SourceEditor, SourceInline)

var ErrAborted = errors.New("aborted")  // returned on Ctrl+C / Esc; main maps to graceful exit
```

## Rules

- No `os.Exit` outside `cmd/ghsec/main.go`. No `panic`.
- Every network call takes `context.Context` and has a timeout (30s default).
- All user-visible strings are English, friendly, actionable — never dump raw JSON/stack.
- Ctrl+C at any prompt must return `tui.ErrAborted` (or `huh.ErrUserAborted` wrapped) so config writes never happen mid-flight.
- `gofmt -l .` must be clean; `go vet ./...` clean; `go build ./...` clean before you report done.
