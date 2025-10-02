package redteamclient

import (
	"time"
)

type RedTeamConfig struct {
	Target  AIScanTarget  `json:"target" yaml:"target"`
	Options AIScanOptions `json:"options" yaml:"options"`
}

type AIScanTarget struct {
	URL  string `json:"url" yaml:"url"`
	Name string `json:"name" yaml:"name"`
}

type AIScanOptions struct {
	Settings        AIScanSettings `json:"settings" yaml:"settings"`
	Vulnerabilities []string       `json:"vulnerabilities" yaml:"vulnerabilities"`
}

type AIScanSettings struct {
	Headers             string `json:"headers,omitempty" yaml:"headers,omitempty"`
	ResponseSelector    string `json:"response_selector" yaml:"response_selector"`
	RequestBodyTemplate string `json:"request_body_template" yaml:"request_body_template"`
}

type AIScan struct {
	ID        string        `json:"id"`
	Status    string        `json:"status"`
	Created   time.Time     `json:"created"`
	Started   *time.Time    `json:"started,omitempty"`
	Completed *time.Time    `json:"completed,omitempty"`
	Target    AIScanTarget  `json:"target"`
	Criticals *int          `json:"criticals,omitempty"`
	Highs     *int          `json:"highs,omitempty"`
	Mediums   *int          `json:"mediums,omitempty"`
	Lows      *int          `json:"lows,omitempty"`
	Options   AIScanOptions `json:"options"`
}

// ScanData is an alias for AIScan to maintain compatibility with existing client code
type ScanData = AIScan

type AIVulnerability struct {
	ID         string                   `json:"vid"`
	URL        string                   `json:"url"`
	Severity   string                   `json:"severity"`
	Confidence *float64                 `json:"confidence,omitempty"`
	Input      *VulnerabilityInput      `json:"input,omitempty"`
	CVSS       *VulnerabilityCVSS       `json:"cvss,omitempty"`
	Evidence   *AIVulnerabilityEvidence `json:"evidence,omitempty"`
	Requests   []string                 `json:"requests,omitempty"`
	Responses  []string                 `json:"responses,omitempty"`
}

type AIVulnerabilityEvidence struct {
	Type    string       `json:"type"`
	Content *interface{} `json:"content,omitempty"`
}

type VulnerabilityInput struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

type VulnerabilityCVSS struct {
	Vector string  `json:"vector"`
	Score  float64 `json:"score"`
}

type AIVulnerabilityDefinition struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
}

type AIVulnerabilityRequestResponsePair struct {
	Request  *string `json:"request,omitempty"`
	Response *string `json:"response,omitempty"`
}

type ScanResultsData struct {
	ID      string            `json:"id"`
	Results []AIVulnerability `json:"results"`
}

// Vulnerability is an alias for AIVulnerability to maintain compatibility
type Vulnerability = AIVulnerability

type CreateAIScanRequest struct {
	Data RedTeamConfig `json:"data"`
}

type CreateAIScanResponse struct {
	Data    AIScan  `json:"data"`
	Jsonapi JSONAPI `json:"jsonapi"`
}

type GetAIScanResponse struct {
	Data    AIScan  `json:"data"`
	Jsonapi JSONAPI `json:"jsonapi"`
}

type GetAIVulnerabilitiesResponse struct {
	Data    []AIVulnerability `json:"data"`
	Jsonapi JSONAPI           `json:"jsonapi"`
}

// Legacy response types for backward compatibility
type ScanListResponse struct {
	Data    []ScanData `json:"data"`
	Jsonapi JSONAPI    `json:"jsonapi"`
}

type CreateScanRequestBody struct {
	Data RedTeamConfig `json:"data"`
}

type CreateScanResponseBody = CreateAIScanResponse

type GetScanResponseBody = GetAIScanResponse

type GetScanResultsResponseBody struct {
	Data    ScanResultsData `json:"data"`
	Jsonapi JSONAPI         `json:"jsonapi"`
}

type JSONAPI struct {
	Version string `json:"version"`
}
