package redteamclient

import (
	"time"

	"github.com/google/uuid"
)

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

type GetScanResponseData struct {
	ID         uuid.UUID      `json:"id"`
	Type       string         `json:"type"`
	Attributes ScanAttributes `json:"attributes"`
}

type ScanData struct {
	ID         uuid.UUID      `json:"id"`
	Type       string         `json:"type"`
	Attributes ScanAttributes `json:"attributes"`
}

type ScanAttributes struct {
	Status    string        `json:"status"`
	CreatedAt time.Time     `json:"created_at"`
	UpdatedAt time.Time     `json:"updated_at"`
	Config    RedTeamConfig `json:"config"`
	Results   ScanResults   `json:"results"`
}

type ScanStatus struct {
	ID         uuid.UUID      `json:"id"`
	Type       string         `json:"type"`
	Attributes ScanAttributes `json:"attributes"`
}

type ScanSummary struct {
	ID         uuid.UUID      `json:"id"`
	Type       string         `json:"type"`
	Attributes ScanAttributes `json:"attributes"`
}

type ScanListResponse struct {
	Data    []ScanSummary `json:"data"`
	Jsonapi JSONAPI       `json:"jsonapi"`
}

type JSONAPI struct {
	Version string `json:"version"`
}

type GetScanResultsResponseBody struct {
	Data    ScanResultsData `json:"data"`
	Jsonapi JSONAPI         `json:"jsonapi"`
}

type ScanResultsData struct {
	ID         uuid.UUID      `json:"id"`
	Type       string         `json:"type"`
	Attributes ScanAttributes `json:"attributes"`
}

type ScanResults struct {
	SuccessfulAttacks int      `json:"successful_attacks"`
	Attacks           []Attack `json:"attacks"`
}

type Attack struct {
	Success        bool           `json:"success"`
	Type           string         `json:"type"`
	RiskCategories []string       `json:"risk_categories"`
	Severity       string         `json:"severity"`
	Description    string         `json:"description"`
	Conversation   []Conversation `json:"conversation"`
}

type Conversation struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
