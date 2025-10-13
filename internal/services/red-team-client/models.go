package redteamclient

import (
	"time"
)

type RedTeamConfig struct {
	Target  AIScanTarget  `json:"target" yaml:"target" validate:"required"`
	Options AIScanOptions `json:"options" yaml:"options"`
}

type AIScanContext struct {
	Purpose string `json:"purpose" yaml:"purpose" validate:"required"`
}

type AIScanTarget struct {
	Name     string         `json:"name" yaml:"name" validate:"required"`
	Type     string         `json:"type" yaml:"type" validate:"required,oneof=api socket_io"`
	Context  AIScanContext  `json:"context" yaml:"context"`
	Settings AIScanSettings `json:"settings" yaml:"settings" validate:"required"`
}

type AIScanOptions struct {
	VulnDefinitions AIScanOptionsVulnDefinitions `json:"vuln_definitions" yaml:"vuln_definitions"` //nolint:tagliatelle // matches OpenAPI spec
}

// AIScanOptionsVulnDefinitions represents vulnerability definitions for an AI scan.
type AIScanOptionsVulnDefinitions struct {
	Exclude []string `json:"exclude,omitempty" yaml:"exclude,omitempty"`
}

type AIScanSettings struct {
	URL                       string                 `json:"url" yaml:"url" validate:"required,url"`
	Headers                   []AIScanSettingsHeader `json:"headers,omitempty" yaml:"headers,omitempty"`
	ResponseSelector          string                 `json:"response_selector" yaml:"response_selector" validate:"required"`
	RequestBodyTemplate       string                 `json:"request_body_template" yaml:"request_body_template" validate:"required,json"`
	SocketIOPath              string                 `json:"socketio_path,omitempty" yaml:"socketio_path,omitempty"`
	SocketIONamespace         string                 `json:"socketio_namespace,omitempty" yaml:"socketio_namespace,omitempty"`
	SocketIOSendEventName     string                 `json:"socketio_send_event_name,omitempty" yaml:"socketio_send_event_name,omitempty"`
	SocketIOResponseEventName string                 `json:"socketio_response_event_name,omitempty" yaml:"socketio_response_event_name,omitempty"`
}

// AIScanSettingsHeaders represents the headers for an AI scan.
type AIScanSettingsHeader struct {
	Name  string `json:"name" yaml:"name"`
	Value string `json:"value" yaml:"value"`
}

type AIScan struct {
	ID        string        `json:"id"`
	Type      string        `json:"type"`
	Status    string        `json:"status"`
	Created   *time.Time    `json:"created"`
	Started   *time.Time    `json:"started"`
	Completed *time.Time    `json:"completed"`
	Target    AIScanTarget  `json:"target"`
	Criticals *int          `json:"criticals"`
	Highs     *int          `json:"highs"`
	Mediums   *int          `json:"mediums"`
	Lows      *int          `json:"lows"`
	Options   AIScanOptions `json:"options"`
}

type AIVulnerability struct {
	ID         string                               `json:"vid"`
	URL        string                               `json:"url"`
	Severity   string                               `json:"severity"`
	Confidence *float64                             `json:"confidence,omitempty"`
	Input      *VulnerabilityInput                  `json:"input,omitempty"`
	CVSS       *VulnerabilityCVSS                   `json:"cvss,omitempty"`
	Evidence   string                               `json:"evidence,omitempty"`
	Turns      []AIVulnerabilityRequestResponsePair `json:"turns,omitempty"`
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

type AIVulnerabilityRequestResponsePair struct {
	Request  *string `json:"request,omitempty"`
	Response *string `json:"response,omitempty"`
}

type CreateAIScanRequest struct {
	Data CreateAIScanRequestData `json:"data" validate:"required"`
}

type CreateAIScanRequestData struct {
	Target  AIScanTarget  `json:"target" validate:"required"`
	Options AIScanOptions `json:"options" validate:"required"`
}

type CreateAIScanResponse struct {
	Data    AIScan  `json:"data"`
	Jsonapi JSONAPI `json:"jsonapi"`
}

type GetAIScanResponse struct {
	Data    AIScan  `json:"data"`
	Jsonapi JSONAPI `json:"jsonapi"`
}

type GetAIVulnerabilitiesResponseData struct {
	ID      string            `json:"id"`
	Results []AIVulnerability `json:"results"`
}

type GetAIVulnerabilitiesResponse struct {
	Data    GetAIVulnerabilitiesResponseData `json:"data"`
	Jsonapi JSONAPI                          `json:"jsonapi"`
}

type CancelAIScanResponse struct {
	Data    AIScan  `json:"data"`
	Jsonapi JSONAPI `json:"jsonapi"`
}

type AIScanListResponse struct {
	Data    []AIScan `json:"data"`
	Jsonapi JSONAPI  `json:"jsonapi"`
}

type GetAIVulnerabilitiesResponseBody struct {
	Data    GetAIVulnerabilitiesResponseData `json:"data"`
	Jsonapi JSONAPI                          `json:"jsonapi"`
}

type JSONAPI struct {
	Version string `json:"version"`
}
