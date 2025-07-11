package aibomclient_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	aibom_errors "github.com/snyk/error-catalog-golang-public/aibom"
	snyk_common_errors "github.com/snyk/error-catalog-golang-public/snyk"

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
	token      = "test-token"
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
		ictx.GetUserInterface(),
		userAgent,
		server.URL, // Use the test server URL
		token,
	)

	result, err := client.GenerateAIBOM(context.Background(), orgID, bundleHash)

	assert.Nil(t, err)
	assert.Contains(t, result, "test-ai-bom-content")
}

// CreateAIBOM tests.
func TestGenerateAIBOM_CreateAIBOMUnauthorized(t *testing.T) {
	// Create a test server that returns 401
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isCreateAIBOMReq(r) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
		}
	}))
	defer server.Close()

	logger := loggermock.NewNoOpLogger()
	ictx := frameworkmock.NewMockInvocationContext(t)

	client := aibomclient.NewAiBomClient(
		logger,
		ictx.GetUserInterface(),
		userAgent,
		server.URL,
		token,
	)

	result, err := client.GenerateAIBOM(context.Background(), orgID, bundleHash)

	assert.Equal(t, "", result)
	assert.Equal(t, snyk_common_errors.NewUnauthorisedError("").ErrorCode, err.SnykError.ErrorCode)
	assert.Contains(t, err.SnykError.Detail, "expected status code 202 but got 401")
}

func TestGenerateAIBOM_CreateAIBOMForbidden(t *testing.T) {
	// Create a test server that returns 403
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isCreateAIBOMReq(r) {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(http.StatusText(http.StatusForbidden)))
		}
	}))
	defer server.Close()

	logger := loggermock.NewNoOpLogger()
	ictx := frameworkmock.NewMockInvocationContext(t)

	client := aibomclient.NewAiBomClient(
		logger,
		ictx.GetUserInterface(),
		userAgent,
		server.URL,
		token,
	)

	result, err := client.GenerateAIBOM(context.Background(), orgID, bundleHash)

	assert.Equal(t, "", result)
	assert.Equal(t, aibom_errors.NewForbiddenError("").ErrorCode, err.SnykError.ErrorCode)
	assert.Contains(t, err.SnykError.Detail, "expected status code 202 but got 403")
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
		ictx.GetUserInterface(),
		userAgent,
		server.URL,
		token,
	)

	result, err := client.GenerateAIBOM(context.Background(), orgID, bundleHash)

	assert.Equal(t, "", result)
	assert.Equal(t, aibom_errors.NewInternalError("").ErrorCode, err.SnykError.ErrorCode)
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
		ictx.GetUserInterface(),
		userAgent,
		server.URL,
		token,
	)

	result, err := client.GenerateAIBOM(context.Background(), orgID, bundleHash)

	assert.Equal(t, "", result)
	assert.Equal(t, aibom_errors.NewInternalError("").ErrorCode, err.SnykError.ErrorCode)
	assert.Contains(t, err.SnykError.Detail, "Job is in errored state")
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
		ictx.GetUserInterface(),
		userAgent,
		server.URL,
		token,
	)

	result, err := client.GenerateAIBOM(context.Background(), orgID, bundleHash)

	assert.Equal(t, "", result)
	assert.Equal(t, aibom_errors.NewInternalError("").ErrorCode, err.SnykError.ErrorCode)
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
			expectedErr:    snyk_common_errors.NewUnauthorisedError("").ErrorCode,
			expectedDetail: "expected status code 200 or 303 but got 401",
		},
		{
			name:           "Forbidden",
			statusCode:     http.StatusForbidden,
			expectedErr:    aibom_errors.NewForbiddenError("").ErrorCode,
			expectedDetail: "expected status code 200 or 303 but got 403",
		},
		{
			name:           "NotFound",
			statusCode:     http.StatusNotFound,
			expectedErr:    aibom_errors.NewInternalError("").ErrorCode,
			expectedDetail: "expected status code 200 or 303 but got 404",
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
				ictx.GetUserInterface(),
				userAgent,
				server.URL,
				token,
			)

			result, err := client.GenerateAIBOM(context.Background(), orgID, bundleHash)

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
		ictx.GetUserInterface(),
		userAgent,
		server.URL,
		token,
	)

	result, err := client.GenerateAIBOM(context.Background(), orgID, bundleHash)

	assert.Equal(t, "", result)
	assert.Equal(t, aibom_errors.NewInternalError("").ErrorCode, err.SnykError.ErrorCode)
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
			expectedErr:    aibom_errors.NewForbiddenError("").ErrorCode,
			expectedDetail: "expected status code 200 but got 403",
		},
		{
			name:           "Unauthorized",
			statusCode:     http.StatusUnauthorized,
			expectedErr:    snyk_common_errors.NewUnauthorisedError("").ErrorCode,
			expectedDetail: "expected status code 200 but got 401",
		},
		{
			name:           "NotFound",
			statusCode:     http.StatusNotFound,
			expectedErr:    aibom_errors.NewInternalError("").ErrorCode,
			expectedDetail: "expected status code 200 but got 404",
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
				ictx.GetUserInterface(),
				userAgent,
				server.URL,
				token,
			)

			result, err := client.GenerateAIBOM(context.Background(), orgID, bundleHash)

			assert.Equal(t, "", result)
			assert.Equal(t, tt.expectedErr, err.SnykError.ErrorCode)
			assert.Contains(t, err.SnykError.Detail, tt.expectedDetail)
		})
	}
}
