package redteamclient

import (
	"time"

	"github.com/google/uuid"
)

type JSONAPI struct {
	Version string `json:"version"`
}

type RedTeamConfig struct {
	Options RedTeamOptions `json:"options"`
	Attacks []string       `json:"attacks,omitempty"`
}

type RedTeamOptions struct {
	Target TargetConfig `json:"target"`
}

type TargetConfig struct {
	Name             string            `json:"name"`
	URL              string            `json:"url"`
	Method           string            `json:"method,omitempty"`
	Headers          map[string]string `json:"headers,omitempty"`
	ResponseSelector string            `json:"response_selector,omitempty"`
	RequestTemplate  string            `json:"request_template,omitempty"`
}

type ScanData struct {
	ID         uuid.UUID      `json:"id"`
	Attributes ScanAttributes `json:"attributes"`
}

type ScanStatus string

// TODO: verify statuses.
const (
	ScanStatusQueued    ScanStatus = "queued"
	ScanStatusFailed    ScanStatus = "failed"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusStarted   ScanStatus = "started"
	ScanStatusCanceled  ScanStatus = "canceled"
)

type ScanAttributes struct {
	Status    ScanStatus    `json:"status"`
	CreatedAt time.Time     `json:"created_at"`
	UpdatedAt time.Time     `json:"updated_at"`
	Config    RedTeamConfig `json:"config"`
}

type ScanResultsData struct {
	ID              uuid.UUID       `json:"id"`
	Attributes      ScanAttributes  `json:"attributes"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type VulnerabilitySeverity string

const (
	// VulnerabilitySeverityLow represents a low severity vulnerability.
	VulnerabilitySeverityLow VulnerabilitySeverity = "low"
	// VulnerabilitySeverityMedium represents a medium severity vulnerability.
	VulnerabilitySeverityMedium VulnerabilitySeverity = "medium"
	// VulnerabilitySeverityHigh represents a high severity vulnerability.
	VulnerabilitySeverityHigh VulnerabilitySeverity = "high"
	// VulnerabilitySeverityCritical represents a critical severity vulnerability.
	VulnerabilitySeverityCritical VulnerabilitySeverity = "critical"
)

// Vulnerability represents an ai scan vulnerability.
type Vulnerability struct {
	VID        string                  `json:"vid"`
	URL        string                  `json:"url"`
	Severity   VulnerabilitySeverity   `json:"severity"`
	Confidence float64                 `json:"confidence"`
	Evidence   []VulnerabilityEvidence `json:"evidence"`
	Requests   []string                `json:"requests"`
	Responses  []string                `json:"responses"`
}

// VulnerabilityCVSS implements the CVSS structure for a vulnerability.
type VulnerabilityCVSS struct {
	Vector string  `json:"vector"`
	Score  float64 `json:"score"`
}

// VulnerabilityEvidence implements the evidence structure for a vulnerability.
type VulnerabilityEvidence struct {
	Type    string      `json:"type"`
	Content interface{} `json:"content"`
}

type ScanListResponse struct {
	Data    []ScanData `json:"data"`
	Jsonapi JSONAPI    `json:"jsonapi"`
}

type CreateScanRequestBody struct {
	Data RedTeamConfig `json:"data"`
}

type CreateScanResponseBody struct {
	Data    ScanData `json:"data"`
	Jsonapi JSONAPI  `json:"jsonapi"`
}

type GetScanResponseBody struct {
	Data    ScanData `json:"data"`
	Jsonapi JSONAPI  `json:"jsonapi"`
}

type GetScanResultsResponseBody struct {
	Data    ScanResultsData `json:"data"`
	Jsonapi JSONAPI         `json:"jsonapi"`
}
