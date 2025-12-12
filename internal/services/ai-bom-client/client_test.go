package aibomclient_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	internal_errors "github.com/snyk/cli-extension-ai-bom/internal/errors"

	aibomclient "github.com/snyk/cli-extension-ai-bom/internal/services/ai-bom-client"
	"github.com/snyk/cli-extension-ai-bom/mocks/frameworkmock"
	"github.com/snyk/cli-extension-ai-bom/mocks/loggermock"
)

func isCreateAIBOMReq(r *http.Request) bool {
	return r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/ai_boms")
}

func isGetJobReq(r *http.Request) bool {
	return r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/ai_bom_jobs/")
}

func isGetAIBOMReq(r *http.Request) bool {
	return r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/ai_boms/")
}

const (
	userAgent  = "test-user-agent"
	orgID      = "test-org-id"
	bundleHash = "test-bundle-hash"
)

func TestGenerateAIBOM_Happy(t *testing.T) {
	var jobID string
	var aiBomID string
	pollCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case isCreateAIBOMReq(r):
			jobID = uuid.New().String()
			response := aibomclient.CreateAiBomResponseBody{
				Data: aibomclient.JobData{
					Id: uuid.MustParse(jobID),
				},
			}
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(response)

		case isGetJobReq(r):
			pollCount++
			if pollCount < 3 {
				// Return processing status
				response := aibomclient.GetAiBomResponseJobBody{
					Data: aibomclient.JobData{
						Attributes: aibomclient.JobAttributes{
							Status: aibomclient.JobStateProcessing,
						},
					},
				}
				json.NewEncoder(w).Encode(response)
			} else {
				// Return finished status
				aiBomID = uuid.New().String()
				response := aibomclient.GetAiBomResponseJobBody{
					Data: aibomclient.JobData{
						Attributes: aibomclient.JobAttributes{
							Status: aibomclient.JobStateFinished,
						},
						Relationships: &aibomclient.JobDataRelationships{
							AiBom: aibomclient.RelationshipObjectToOne{
								Data: aibomclient.RelationshipObjectToOneData{
									Id: uuid.MustParse(aiBomID),
								},
							},
						},
					},
				}
				json.NewEncoder(w).Encode(response)
			}

		case isGetAIBOMReq(r):
			// Handle getAIBOM
			response := aibomclient.GetAiBomResponseBody{
				Data: aibomclient.GetAiBomResponseData{
					Attributes: map[string]interface{}{
						"content": "test-ai-bom-content",
						"version": "1.0.0",
					},
				},
			}
			json.NewEncoder(w).Encode(response)

		default:
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		}
	}))
	defer server.Close()

	logger := loggermock.NewNoOpLogger()
	ictx := frameworkmock.NewMockInvocationContext(t)

	client := aibomclient.NewAiBomClient(
		logger,
		ictx.GetNetworkAccess().GetHttpClient(),
		ictx.GetUserInterface(),
		userAgent,
		server.URL, // Use the test server URL
	)

	result, err := client.GenerateAIBOM(t.Context(), orgID, bundleHash)

	assert.Nil(t, err)
	assert.Contains(t, result, "test-ai-bom-content")
}

// CreateAIBOM tests.
func TestGenerateAIBOM_CreateAIBOMAuthErrors(t *testing.T) {
	tests := []struct {
		name               string
		statusCode         int
		expectedErrorCode  string
		expectedStatusText string
	}{
		{
			name:               "Unauthorized",
			statusCode:         http.StatusUnauthorized,
			expectedErrorCode:  internal_errors.NewUnauthorizedError("").SnykError.ErrorCode,
			expectedStatusText: "401",
		},
		{
			name:               "Forbidden",
			statusCode:         http.StatusForbidden,
			expectedErrorCode:  internal_errors.NewForbiddenError("").SnykError.ErrorCode,
			expectedStatusText: "403",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a test server that returns the specified status code
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if isCreateAIBOMReq(r) {
					w.WriteHeader(tc.statusCode)
					w.Write([]byte(http.StatusText(tc.statusCode)))
				}
			}))
			defer server.Close()

			logger := loggermock.NewNoOpLogger()
			ictx := frameworkmock.NewMockInvocationContext(t)

			client := aibomclient.NewAiBomClient(
				logger,
				ictx.GetNetworkAccess().GetHttpClient(),
				ictx.GetUserInterface(),
				userAgent,
				server.URL,
			)

			result, err := client.GenerateAIBOM(t.Context(), orgID, bundleHash)

			assert.Equal(t, "", result)
			assert.Equal(t, tc.expectedErrorCode, err.SnykError.ErrorCode)
			assert.Contains(t, err.SnykError.Detail, "unexpected status code "+tc.expectedStatusText+" for CreateAIBOM")
		})
	}
}

func TestGenerateAIBOM_CreateAIBOMHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isCreateAIBOMReq(r) {
			// Close the connection to simulate network error
			hijacker, _ := w.(http.Hijacker)
			conn, _, _ := hijacker.Hijack()
			conn.Close()
		}
	}))
	defer server.Close()

	logger := loggermock.NewNoOpLogger()
	ictx := frameworkmock.NewMockInvocationContext(t)

	client := aibomclient.NewAiBomClient(
		logger,
		ictx.GetNetworkAccess().GetHttpClient(),
		ictx.GetUserInterface(),
		userAgent,
		server.URL,
	)

	result, err := client.GenerateAIBOM(t.Context(), orgID, bundleHash)

	assert.Equal(t, "", result)
	assert.Equal(t, internal_errors.NewInternalError("").SnykError.ErrorCode, err.SnykError.ErrorCode)
	assert.Contains(t, err.SnykError.Detail, "CreateAIBOM request HTTP error")
}

// GetAIBOMJob tests.
func TestGenerateAIBOM_JobErrored(t *testing.T) {
	var jobID string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case isCreateAIBOMReq(r):
			jobID = uuid.New().String()
			response := aibomclient.CreateAiBomResponseBody{
				Data: aibomclient.JobData{
					Id: uuid.MustParse(jobID),
				},
			}
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(response)

		case isGetJobReq(r):
			// Handle pollForAIBOM - return errored status
			response := aibomclient.GetAiBomResponseJobBody{
				Data: aibomclient.JobData{
					Attributes: aibomclient.JobAttributes{
						Status: aibomclient.JobStateErrored,
					},
				},
			}
			json.NewEncoder(w).Encode(response)

		default:
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		}
	}))
	defer server.Close()

	logger := loggermock.NewNoOpLogger()
	ictx := frameworkmock.NewMockInvocationContext(t)

	client := aibomclient.NewAiBomClient(
		logger,
		ictx.GetNetworkAccess().GetHttpClient(),
		ictx.GetUserInterface(),
		userAgent,
		server.URL,
	)

	result, err := client.GenerateAIBOM(t.Context(), orgID, bundleHash)

	assert.Equal(t, "", result)
	assert.Equal(t, internal_errors.NewInternalError("").SnykError.ErrorCode, err.SnykError.ErrorCode)
	assert.Contains(t, err.SnykError.Detail, "Failed to execute job")
}

func TestGenerateAIBOM_PollForAIBOMHTTPError(t *testing.T) {
	var jobID string
	requestCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		switch {
		case isCreateAIBOMReq(r):
			jobID = uuid.New().String()
			response := aibomclient.CreateAiBomResponseBody{
				Data: aibomclient.JobData{
					Id: uuid.MustParse(jobID),
				},
			}
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(response)

		case isGetJobReq(r):
			// Handle pollForAIBOM - simulate HTTP error
			hijacker, _ := w.(http.Hijacker)
			conn, _, _ := hijacker.Hijack()
			conn.Close()

		default:
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		}
	}))
	defer server.Close()

	logger := loggermock.NewNoOpLogger()
	ictx := frameworkmock.NewMockInvocationContext(t)

	client := aibomclient.NewAiBomClient(
		logger,
		ictx.GetNetworkAccess().GetHttpClient(),
		ictx.GetUserInterface(),
		userAgent,
		server.URL,
	)

	result, err := client.GenerateAIBOM(t.Context(), orgID, bundleHash)

	assert.Equal(t, "", result)
	assert.Equal(t, internal_errors.NewInternalError("").SnykError.ErrorCode, err.SnykError.ErrorCode)
	assert.Contains(t, err.SnykError.Detail, "GetAIBOMJob request HTTP error")
}

func TestGenerateAIBOM_PollForAIBOMAuthAndNotFoundErrors(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		statusText     string
		expectedErr    string
		expectedDetail string
	}{
		{
			name:           "Unauthorized",
			statusCode:     http.StatusUnauthorized,
			expectedErr:    internal_errors.NewUnauthorizedError("").SnykError.ErrorCode,
			expectedDetail: "unexpected status code 401 for GetAIBOMJob",
		},
		{
			name:           "Forbidden",
			statusCode:     http.StatusForbidden,
			expectedErr:    internal_errors.NewForbiddenError("").SnykError.ErrorCode,
			expectedDetail: "unexpected status code 403 for GetAIBOMJob",
		},
		{
			name:           "NotFound",
			statusCode:     http.StatusNotFound,
			expectedErr:    internal_errors.NewInternalError("").SnykError.ErrorCode,
			expectedDetail: "unexpected status code 404 for GetAIBOMJob",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var jobID string

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case isCreateAIBOMReq(r):
					jobID = uuid.New().String()
					response := aibomclient.CreateAiBomResponseBody{
						Data: aibomclient.JobData{
							Id: uuid.MustParse(jobID),
						},
					}
					w.WriteHeader(http.StatusAccepted)
					json.NewEncoder(w).Encode(response)

				case isGetJobReq(r):
					w.WriteHeader(tt.statusCode)
					w.Write([]byte(http.StatusText(tt.statusCode)))

				default:
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				}
			}))
			defer server.Close()

			logger := loggermock.NewNoOpLogger()
			ictx := frameworkmock.NewMockInvocationContext(t)

			client := aibomclient.NewAiBomClient(
				logger,
				ictx.GetNetworkAccess().GetHttpClient(),
				ictx.GetUserInterface(),
				userAgent,
				server.URL,
			)

			result, err := client.GenerateAIBOM(t.Context(), orgID, bundleHash)

			assert.Equal(t, "", result)
			if assert.NotNil(t, err) {
				assert.Equal(t, tt.expectedErr, err.SnykError.ErrorCode)
				assert.Contains(t, err.SnykError.Detail, tt.expectedDetail)
			}
		})
	}
}

// GetAIBOM tests.
func TestGenerateAIBOM_GetAIBOMHTTPError(t *testing.T) {
	var jobID string
	var aiBomID string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case isCreateAIBOMReq(r):
			jobID = uuid.New().String()
			response := aibomclient.CreateAiBomResponseBody{
				Data: aibomclient.JobData{
					Id: uuid.MustParse(jobID),
				},
			}
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(response)

		case isGetJobReq(r):
			aiBomID = uuid.New().String()
			response := aibomclient.GetAiBomResponseJobBody{
				Data: aibomclient.JobData{
					Attributes: aibomclient.JobAttributes{
						Status: aibomclient.JobStateFinished,
					},
					Relationships: &aibomclient.JobDataRelationships{
						AiBom: aibomclient.RelationshipObjectToOne{
							Data: aibomclient.RelationshipObjectToOneData{
								Id: uuid.MustParse(aiBomID),
							},
						},
					},
				},
			}
			json.NewEncoder(w).Encode(response)

		case isGetAIBOMReq(r):
			// Handle getAIBOM - simulate HTTP error
			hijacker, _ := w.(http.Hijacker)
			conn, _, _ := hijacker.Hijack()
			conn.Close()

		default:
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		}
	}))
	defer server.Close()

	logger := loggermock.NewNoOpLogger()
	ictx := frameworkmock.NewMockInvocationContext(t)

	client := aibomclient.NewAiBomClient(
		logger,
		ictx.GetNetworkAccess().GetHttpClient(),
		ictx.GetUserInterface(),
		userAgent,
		server.URL,
	)

	result, err := client.GenerateAIBOM(t.Context(), orgID, bundleHash)

	assert.Equal(t, "", result)
	assert.Equal(t, internal_errors.NewInternalError("").SnykError.ErrorCode, err.SnykError.ErrorCode)
	assert.Contains(t, err.SnykError.Detail, "GetAIBOM request HTTP error")
}

func TestGenerateAIBOM_GetAIBOMAuthErrors(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		statusText     string
		expectedErr    string
		expectedDetail string
	}{
		{
			name:           "Forbidden",
			statusCode:     http.StatusForbidden,
			expectedErr:    internal_errors.NewForbiddenError("").SnykError.ErrorCode,
			expectedDetail: "unexpected status code 403 for GetAIBOM",
		},
		{
			name:           "Unauthorized",
			statusCode:     http.StatusUnauthorized,
			expectedErr:    internal_errors.NewUnauthorizedError("").SnykError.ErrorCode,
			expectedDetail: "unexpected status code 401 for GetAIBOM",
		},
		{
			name:           "NotFound",
			statusCode:     http.StatusNotFound,
			expectedErr:    internal_errors.NewInternalError("").SnykError.ErrorCode,
			expectedDetail: "unexpected status code 404 for GetAIBOM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var jobID string
			var aiBomID string

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case isCreateAIBOMReq(r):
					jobID = uuid.New().String()
					response := aibomclient.CreateAiBomResponseBody{
						Data: aibomclient.JobData{
							Id: uuid.MustParse(jobID),
						},
					}
					w.WriteHeader(http.StatusAccepted)
					json.NewEncoder(w).Encode(response)

				case isGetJobReq(r):
					aiBomID = uuid.New().String()
					response := aibomclient.GetAiBomResponseJobBody{
						Data: aibomclient.JobData{
							Attributes: aibomclient.JobAttributes{
								Status: aibomclient.JobStateFinished,
							},
							Relationships: &aibomclient.JobDataRelationships{
								AiBom: aibomclient.RelationshipObjectToOne{
									Data: aibomclient.RelationshipObjectToOneData{
										Id: uuid.MustParse(aiBomID),
									},
								},
							},
						},
					}
					json.NewEncoder(w).Encode(response)

				case isGetAIBOMReq(r):
					w.WriteHeader(tt.statusCode)
					w.Write([]byte(http.StatusText(tt.statusCode)))

				default:
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				}
			}))
			defer server.Close()

			logger := loggermock.NewNoOpLogger()
			ictx := frameworkmock.NewMockInvocationContext(t)

			client := aibomclient.NewAiBomClient(
				logger,
				ictx.GetNetworkAccess().GetHttpClient(),
				ictx.GetUserInterface(),
				userAgent,
				server.URL,
			)

			result, err := client.GenerateAIBOM(t.Context(), orgID, bundleHash)

			assert.Equal(t, "", result)
			assert.Equal(t, tt.expectedErr, err.SnykError.ErrorCode)
			assert.Contains(t, err.SnykError.Detail, tt.expectedDetail)
		})
	}
}
