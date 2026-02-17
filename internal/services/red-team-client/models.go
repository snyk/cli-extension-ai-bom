package redteamclient

import (
	"time"
)

type AIScanStatus string

const (
	AIScanStatusQueued    AIScanStatus = "queued"
	AIScanStatusSubmitted AIScanStatus = "submitted"
	AIScanStatusStarted   AIScanStatus = "started"
	AIScanStatusCompleted AIScanStatus = "completed"
	AIScanStatusFailed    AIScanStatus = "failed"
	AIScanStatusCanceled  AIScanStatus = "canceled"
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
	Type     string         `json:"type" yaml:"type" validate:"required"`
	Context  AIScanContext  `json:"context" yaml:"context"`
	Settings AIScanSettings `json:"settings" yaml:"settings" validate:"required"`
}

type AIScanOptions struct {
	VulnDefinitions AIScanOptionsVulnDefinitions `json:"vuln_definitions" yaml:"vuln_definitions"` //nolint:tagliatelle // matches OpenAPI spec
	ScanningAgent   string                       `json:"scanning_agent,omitempty" yaml:"scanning_agent,omitempty" validate:"omitempty,uuid"`
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
	Name  string `json:"name" yaml:"name" validate:"required"`
	Value string `json:"value" yaml:"value" validate:"required"`
}

type AIScan struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	Status    AIScanStatus   `json:"status"`
	Created   *time.Time     `json:"created"`
	Started   *time.Time     `json:"started"`
	Completed *time.Time     `json:"completed"`
	Target    AIScanTarget   `json:"target"`
	Criticals *int           `json:"criticals"`
	Highs     *int           `json:"highs"`
	Mediums   *int           `json:"mediums"`
	Lows      *int           `json:"lows"`
	Options   AIScanOptions  `json:"options"`
	Feedback  AIScanFeedback `json:"feedback"`
}

// AIScanFeedback represents the feedback for an AI scan.
type AIScanFeedback struct {
	Status  *AIScanFeedbackStatus `json:"status,omitempty"`
	Warning []AIScanFeedbackIssue `json:"warning,omitempty"`
	Error   []AIScanFeedbackIssue `json:"error,omitempty"`
}

// AIScanFeedbackIssue represents an error or a warning for an AI scan feedback.
type AIScanFeedbackIssue struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// AIScanFeedbackStatus represents the status of an AI scan feedback.
type AIScanFeedbackStatus struct {
	Done  *int `json:"done"`
	Total *int `json:"total"`
}

type AIVulnerability struct {
	ID         string                    `json:"id"`
	Definition AIVulnerabilityDefinition `json:"definition"`
	Tags       []string                  `json:"tags,omitempty"`
	Severity   string                    `json:"severity"`
	URL        string                    `json:"url"`
	Turns      []Turn                    `json:"turns,omitempty"`
	Evidence   AIVulnerabilityEvidence   `json:"evidence,omitempty"`
}

type Turn struct {
	Request  *string `json:"request,omitempty"`
	Response *string `json:"response,omitempty"`
}

type AIVulnerabilityEvidence struct {
	Type    string                         `json:"type"`
	Content AIVulnerabilityEvidenceContent `json:"content"`
}

type AIVulnerabilityEvidenceContent struct {
	Reason string `json:"reason"`
}

type AIVulnerabilityDefinition struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
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

type JSONAPI struct {
	Version string `json:"version"`
}

type AIScanningAgentInput struct {
	Name string `json:"name"`
}

type PaginatedAIScanningAgentList struct {
	Count     int               `json:"count"`
	PageTotal int               `json:"page_total"` //nolint:tagliatelle // matches OpenAPI spec
	Page      int               `json:"page"`
	Length    int               `json:"length"`
	Results   []AIScanningAgent `json:"results"`
}

type AIScanningAgent struct {
	Name               string `json:"name"`
	InstallerGenerated bool   `json:"installer_generated"`
	ID                 string `json:"id"`
	Online             bool   `json:"online"`
	Fallback           bool   `json:"fallback"`
	RXBytes            int    `json:"rx_bytes"`
	TXBytes            int    `json:"tx_bytes"`
	LatestHandshake    int    `json:"latest_handshake"`
}

type AIScanningAgentConfig struct {
	Token string `json:"token"`
}

type CreateAIScanningAgentRequest struct {
	Data AIScanningAgentInput `json:"data" validate:"required"`
}

type CreateAIScanningAgentResponse struct {
	Data    AIScanningAgent `json:"data"`
	Jsonapi JSONAPI         `json:"jsonapi"`
}

type GetAIScanningAgentResponse struct {
	Data    AIScanningAgent `json:"data"`
	Jsonapi JSONAPI         `json:"jsonapi"`
}

type ListAIScanningAgentsResponse struct {
	Data    []AIScanningAgent `json:"data"`
	Jsonapi JSONAPI           `json:"jsonapi"`
}

type GenerateAIScanningAgentConfigData struct {
	FarcasterAgentToken string `json:"farcaster_agent_token"`
	FarcasterAPIURL     string `json:"farcaster_api_url"`
}

type GenerateAIScanningAgentConfigResponse struct {
	Data    GenerateAIScanningAgentConfigData `json:"data"`
	Jsonapi JSONAPI                           `json:"jsonapi"`
}
