package api

// This file models the full GitHub repository-advisory resource as documented in
// the official OpenAPI description (api.github.com, 2022-11-28). The deliberately
// small Advisory struct in types.go stays as the write-path result type; the
// richer types below back the read, edit and collaboration features.

import (
	"fmt"
	"strings"
)

// AdvisoryState is the lifecycle state of a repository advisory.
type AdvisoryState string

// Advisory states accepted by PATCH /repos/{owner}/{repo}/security-advisories/{ghsa_id}.
const (
	StateDraft     AdvisoryState = "draft"
	StateTriage    AdvisoryState = "triage"
	StatePublished AdvisoryState = "published"
	StateClosed    AdvisoryState = "closed"
)

// AdvisoryStates lists every state the list endpoint can filter on.
var AdvisoryStates = []AdvisoryState{StateTriage, StateDraft, StatePublished, StateClosed}

// EditableStates lists the states PATCH accepts (triage is not settable).
var EditableStates = []AdvisoryState{StateDraft, StatePublished, StateClosed}

// Valid reports whether s is a known advisory state.
func (s AdvisoryState) Valid() bool {
	switch s {
	case StateDraft, StateTriage, StatePublished, StateClosed:
		return true
	default:
		return false
	}
}

// Editable reports whether PATCH can move an advisory into this state.
func (s AdvisoryState) Editable() bool {
	switch s {
	case StateDraft, StatePublished, StateClosed:
		return true
	default:
		return false
	}
}

// ParseAdvisoryState normalises user input.
func ParseAdvisoryState(raw string) (AdvisoryState, error) {
	s := AdvisoryState(strings.ToLower(strings.TrimSpace(raw)))
	if !s.Valid() {
		return "", fmt.Errorf("invalid state %q: must be one of draft, triage, published, closed", raw)
	}
	return s, nil
}

// Label returns a display-friendly state name.
func (s AdvisoryState) Label() string {
	switch s {
	case StateDraft:
		return "Draft"
	case StateTriage:
		return "Triage"
	case StatePublished:
		return "Published"
	case StateClosed:
		return "Closed"
	default:
		return string(s)
	}
}

// User is a GitHub account reference embedded in resources.
type SimpleUser struct {
	Login     string `json:"login"`
	ID        int64  `json:"id"`
	HTMLURL   string `json:"html_url"`
	AvatarURL string `json:"avatar_url"`
	Type      string `json:"type"`
}

// LoginOrUnknown returns the login, or a placeholder for deleted accounts.
func (u *SimpleUser) LoginOrUnknown() string {
	if u == nil || strings.TrimSpace(u.Login) == "" {
		return "(unknown)"
	}
	return u.Login
}

// Package identifies an affected package.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// String renders "ecosystem:name".
func (p Package) String() string {
	switch {
	case p.Ecosystem == "" && p.Name == "":
		return ""
	case p.Ecosystem == "":
		return p.Name
	case p.Name == "":
		return p.Ecosystem
	default:
		return p.Ecosystem + ":" + p.Name
	}
}

// Vulnerability is one affected-package entry of an advisory.
type Vulnerability struct {
	Package                Package  `json:"package"`
	VulnerableVersionRange string   `json:"vulnerable_version_range"`
	PatchedVersions        string   `json:"patched_versions"`
	VulnerableFunctions    []string `json:"vulnerable_functions"`
}

// Credit is a person credited for the advisory.
type Credit struct {
	Login string `json:"login"`
	Type  string `json:"type"`
}

// CVSS holds the computed score for an advisory.
type CVSS struct {
	VectorString string  `json:"vector_string"`
	Score        float64 `json:"score"`
}

// Identifier is a cross-reference such as a CVE id.
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// AdvisoryDetail is the complete advisory resource used by the browser, editor
// and CLI. It intentionally mirrors GitHub's field names.
type AdvisoryDetail struct {
	GHSAID             string           `json:"ghsa_id"`
	CVEID              string           `json:"cve_id"`
	URL                string           `json:"url"`
	HTMLURL            string           `json:"html_url"`
	Summary            string           `json:"summary"`
	Description        string           `json:"description"`
	Severity           string           `json:"severity"`
	State              string           `json:"state"`
	CreatedAt          string           `json:"created_at"`
	UpdatedAt          string           `json:"updated_at"`
	PublishedAt        string           `json:"published_at"`
	ClosedAt           string           `json:"closed_at"`
	WithdrawnAt        string           `json:"withdrawn_at"`
	Author             *SimpleUser      `json:"author"`
	Publisher          *SimpleUser      `json:"publisher"`
	Identifiers        []Identifier     `json:"identifiers"`
	Vulnerabilities    []Vulnerability  `json:"vulnerabilities"`
	CVSS               *CVSS            `json:"cvss"`
	CVSSSeverities     *CVSSSeverities  `json:"cvss_severities"`
	CWEIDs             []string         `json:"cwe_ids"`
	CWEs               []CWE            `json:"cwes"`
	Credits            []Credit         `json:"credits"`
	CreditsDetailed    []CreditDetailed `json:"credits_detailed"`
	CollaboratingUsers []SimpleUser     `json:"collaborating_users"`
	CollaboratingTeams []TeamRef        `json:"collaborating_teams"`
	Submission         *Submission      `json:"submission"`
	PrivateFork        *PrivateFork     `json:"private_fork"`
}

// CWE is a weakness classification.
type CWE struct {
	CWEID string `json:"cwe_id"`
	Name  string `json:"name"`
}

// CVSSSeverities groups the CVSS v3 and v4 vectors.
type CVSSSeverities struct {
	CVSSV3 *CVSSv3 `json:"cvss_v3"`
	CVSSV4 *CVSSv4 `json:"cvss_v4"`
}

// CVSSv3 is a CVSS 3.x vector and score.
type CVSSv3 struct {
	VectorString string  `json:"vector_string"`
	Score        float64 `json:"score"`
}

// CVSSv4 is a CVSS 4.0 vector and score.
type CVSSv4 struct {
	VectorString string  `json:"vector_string"`
	Score        float64 `json:"score"`
}

// CreditDetailed is the expanded form of a credit.
type CreditDetailed struct {
	User *SimpleUser `json:"user"`
	Type string      `json:"type"`
}

// TeamRef is an organisation team reference.
type TeamRef struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// Submission records whether GitHub accepted the advisory into the curation queue.
type Submission struct {
	Accepted bool `json:"accepted"`
}

// PrivateFork is the temporary private fork created for collaboration.
type PrivateFork struct {
	ID       int64       `json:"id"`
	FullName string      `json:"full_name"`
	HTMLURL  string      `json:"html_url"`
	Owner    *SimpleUser `json:"owner"`
}

// AdvisoryStateValue returns the parsed state, tolerating unknown values.
func (a *AdvisoryDetail) AdvisoryStateValue() AdvisoryState {
	if a == nil {
		return ""
	}
	return AdvisoryState(strings.ToLower(a.State))
}

// Identifier returns the best available human identifier.
func (a *AdvisoryDetail) Identifier() string {
	if a == nil {
		return ""
	}
	switch {
	case a.GHSAID != "":
		return a.GHSAID
	case a.CVEID != "":
		return a.CVEID
	default:
		return "(unknown id)"
	}
}

// IsOpen reports whether the advisory is still being worked on.
func (a *AdvisoryDetail) IsOpen() bool {
	switch a.AdvisoryStateValue() {
	case StateDraft, StateTriage:
		return true
	default:
		return false
	}
}

// AuthorLogin returns the advisory author's login.
func (a *AdvisoryDetail) AuthorLogin() string {
	if a == nil {
		return ""
	}
	return a.Author.LoginOrUnknown()
}

// AffectedSummary renders a one-line description of affected packages.
func (a *AdvisoryDetail) AffectedSummary() string {
	if a == nil || len(a.Vulnerabilities) == 0 {
		return ""
	}
	parts := make([]string, 0, len(a.Vulnerabilities))
	for _, v := range a.Vulnerabilities {
		label := v.Package.String()
		if label == "" {
			label = "unknown package"
		}
		if rangeText := strings.TrimSpace(v.VulnerableVersionRange); rangeText != "" {
			label += " " + rangeText
		}
		parts = append(parts, label)
	}
	return strings.Join(parts, ", ")
}

// CVSSScoreText renders the score, or a dash when absent.
func (a *AdvisoryDetail) CVSSScoreText() string {
	if a == nil {
		return "—"
	}
	switch {
	case a.CVSS != nil && a.CVSS.Score > 0:
		return fmt.Sprintf("%.1f", a.CVSS.Score)
	case a.CVSSSeverities != nil && a.CVSSSeverities.CVSSV4 != nil && a.CVSSSeverities.CVSSV4.Score > 0:
		return fmt.Sprintf("%.1f", a.CVSSSeverities.CVSSV4.Score)
	case a.CVSSSeverities != nil && a.CVSSSeverities.CVSSV3 != nil && a.CVSSSeverities.CVSSV3.Score > 0:
		return fmt.Sprintf("%.1f", a.CVSSSeverities.CVSSV3.Score)
	default:
		return "—"
	}
}

// CVEState describes the CVE lifecycle as far as GitHub exposes it.
//
// GitHub does not return an explicit "CVE requested" flag on the advisory
// resource; a CVE id appearing is the observable signal that NVD/GitHub issued
// one. This helper makes that explicit instead of guessing.
type CVEState string

// Possible CVE states.
const (
	CVEAssigned CVEState = "assigned"
	CVEPending  CVEState = "not assigned"
)

// CVEStatus derives the CVE state for an advisory.
func (a *AdvisoryDetail) CVEStatus() CVEState {
	if a == nil || strings.TrimSpace(a.CVEID) == "" {
		return CVEPending
	}
	return CVEAssigned
}

// CVEPendingReports lists CVEs still awaiting an id, per identifiers.
func (a *AdvisoryDetail) CVEPendingReports() bool {
	if a == nil {
		return false
	}
	for _, id := range a.Identifiers {
		if strings.EqualFold(id.Type, "CVE") && strings.TrimSpace(id.Value) != "" {
			return false
		}
	}
	return strings.TrimSpace(a.CVEID) == ""
}

// Comment is a repository advisory comment (a reply in the advisory thread).
type Comment struct {
	ID                int64       `json:"id"`
	NodeID            string      `json:"node_id"`
	URL               string      `json:"url"`
	HTMLURL           string      `json:"html_url"`
	Body              string      `json:"body"`
	User              *SimpleUser `json:"user"`
	CreatedAt         string      `json:"created_at"`
	UpdatedAt         string      `json:"updated_at"`
	AdvisoryURL       string      `json:"advisory_url"`
	AuthorAssociation string      `json:"author_association"`
}

// AuthorLogin returns the commenter's login.
func (c *Comment) AuthorLogin() string {
	if c == nil {
		return ""
	}
	return c.User.LoginOrUnknown()
}

// AdvisoryListOptions selects a page of advisories.
type AdvisoryListOptions struct {
	State     AdvisoryState // empty = all states
	Sort      string        // created (default), updated, published
	Direction string        // asc, desc
	PerPage   int           // 1..100, default 30
	Page      int           // 1-based
}

// AdvisoryUpdatePatch carries only the fields the caller wants to change.
//
// Pointer fields distinguish "leave unchanged" (nil) from "set to empty", which
// matters for clearing a CVE id or a CVSS vector.
type AdvisoryUpdatePatch struct {
	Summary            *string         `json:"summary,omitempty"`
	Description        *string         `json:"description,omitempty"`
	CVEID              *string         `json:"cve_id,omitempty"`
	Severity           *Severity       `json:"-"`
	CWEIDs             *[]string       `json:"cwe_ids,omitempty"`
	State              *AdvisoryState  `json:"-"`
	Vulnerabilities    []Vulnerability `json:"vulnerabilities,omitempty"`
	CVSSVectorString   *string         `json:"cvss_vector_string,omitempty"`
	CollaboratingUsers []string        `json:"collaborating_users,omitempty"`
	CollaboratingTeams []string        `json:"collaborating_teams,omitempty"`
}

// IsEmpty reports whether the patch would change nothing.
func (p AdvisoryUpdatePatch) IsEmpty() bool {
	return p.Summary == nil && p.Description == nil && p.CVEID == nil && p.Severity == nil &&
		p.CWEIDs == nil && p.State == nil && len(p.Vulnerabilities) == 0 &&
		p.CVSSVectorString == nil && len(p.CollaboratingUsers) == 0 && len(p.CollaboratingTeams) == 0
}

// toWire converts the patch to the JSON shape GitHub expects.
func (p AdvisoryUpdatePatch) toWire() map[string]any {
	out := map[string]any{}
	if p.Summary != nil {
		out["summary"] = *p.Summary
	}
	if p.Description != nil {
		out["description"] = *p.Description
	}
	if p.CVEID != nil {
		out["cve_id"] = *p.CVEID
	}
	if p.Severity != nil {
		out["severity"] = string(*p.Severity)
	}
	if p.CWEIDs != nil {
		out["cwe_ids"] = *p.CWEIDs
	}
	if p.State != nil {
		out["state"] = string(*p.State)
	}
	if len(p.Vulnerabilities) > 0 {
		out["vulnerabilities"] = p.Vulnerabilities
	}
	if p.CVSSVectorString != nil {
		out["cvss_vector_string"] = *p.CVSSVectorString
	}
	if len(p.CollaboratingUsers) > 0 {
		out["collaborating_users"] = p.CollaboratingUsers
	}
	if len(p.CollaboratingTeams) > 0 {
		out["collaborating_teams"] = p.CollaboratingTeams
	}
	return out
}

// ListPage carries one page of results plus paging information.
type ListPage[T any] struct {
	Items      []T
	NextPage   int // 0 when there is no next page
	TotalCount int // -1 when unknown
	HasMore    bool
}
