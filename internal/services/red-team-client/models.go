package redteamclient

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// RedTeamConfig represents the configuration for a red team scan.
type RedTeamConfig struct {
	Options RedTeamOptions `json:"options"`
	Attacks []string       `json:"attacks,omitempty"`
}

// RedTeamOptions represents the options for a red team scan.
type RedTeamOptions struct {
	Target TargetConfig `json:"target"`
}

// TargetConfig represents the target configuration.
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

// CreateScanResponseBody represents the response body for creating a scan.
type CreateScanResponseBody struct {
	Data    ScanData `json:"data"`
	Jsonapi JsonApi  `json:"jsonapi"`
	Links   Links    `json:"links"`
}

// ScanData represents scan data in API responses.
type ScanData struct {
	Id         uuid.UUID      `json:"id"`
	Type       string         `json:"type"`
	Attributes ScanAttributes `json:"attributes"`
}

// ScanAttributes represents scan attributes.
type ScanAttributes struct {
	Status    string        `json:"status"`
	CreatedAt time.Time     `json:"created_at"`
	UpdatedAt time.Time     `json:"updated_at"`
	Config    RedTeamConfig `json:"config"`
}

// ScanStatus represents the status of a scan.
type ScanStatus struct {
	Id         uuid.UUID      `json:"id"`
	Type       string         `json:"type"`
	Attributes ScanAttributes `json:"attributes"`
}

// ScanSummary represents a summary of a scan for listing.
type ScanSummary struct {
	Id         uuid.UUID      `json:"id"`
	Type       string         `json:"type"`
	Attributes ScanAttributes `json:"attributes"`
}

// ScanListResponse represents the response for listing scans.
type ScanListResponse struct {
	Data    []ScanSummary `json:"data"`
	Jsonapi JsonApi       `json:"jsonapi"`
	Links   Links         `json:"links"`
}

// JsonApi represents JSON API metadata.
type JsonApi struct {
	Version string `json:"version"`
}

// Links represents pagination links.
type Links struct {
	First *LinkProperty `json:"first,omitempty"`
	Last  *LinkProperty `json:"last,omitempty"`
	Next  *LinkProperty `json:"next,omitempty"`
	Prev  *LinkProperty `json:"prev,omitempty"`
	Self  *LinkProperty `json:"self,omitempty"`
}

// LinkProperty represents a link property.
type LinkProperty struct {
	union json.RawMessage
}

// AsString returns the union data inside the LinkProperty as a string.
func (t LinkProperty) AsString() (string, error) {
	var body string
	err := json.Unmarshal(t.union, &body)
	return body, err
}

// FromString overwrites any union data inside the LinkProperty as the provided string.
func (t *LinkProperty) FromString(v string) error {
	b, err := json.Marshal(v)
	t.union = b
	return err
}

func (t LinkProperty) MarshalJSON() ([]byte, error) {
	b, err := t.union.MarshalJSON()
	return b, err
}

func (t *LinkProperty) UnmarshalJSON(b []byte) error {
	err := t.union.UnmarshalJSON(b)
	return err
}
