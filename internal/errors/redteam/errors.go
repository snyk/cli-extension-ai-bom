package redteam

import (
	"fmt"

	cli_errors "github.com/snyk/error-catalog-golang-public/cli"
	snyk_common_errors "github.com/snyk/error-catalog-golang-public/snyk"
)

// The below pattern has been borrowed from cli-extension-os-flows.
// The issue with SnykError is that it serializes to a Title (that can't be changed)
// rather than the msg provided.

// TODO(pkey): address above by moving to a generic error-catalog interface.
//
//nolint:revive // RedTeamError is intentionally named to match package context
type RedTeamError struct {
	err     error
	userMsg string
}

// This will show up in the details of the error in the CLI.
func (xerr RedTeamError) Error() string {
	return xerr.userMsg
}

// Unwrap implements error.
// NOTE: If an untyped (non-Snyk) error is wrapped, it will be shown
// to the user as Unspecified Error (SNYK-CLI-0000).
func (xerr RedTeamError) Unwrap() error {
	return xerr.err
}

// newRedTeamError creates a new RedTeamError.
func newRedTeamError(err error, userMsg string) *RedTeamError {
	return &RedTeamError{
		err:     err,
		userMsg: userMsg,
	}
}

func NewBadRequestError(msg string) *RedTeamError {
	return newRedTeamError(snyk_common_errors.NewBadRequestError(msg), msg)
}

func NewScanError(msg, scanID string) *RedTeamError {
	return newRedTeamError(cli_errors.NewGeneralCLIFailureError(fmt.Sprintf("Scan ID: %s failed. %s", scanID, msg)), msg)
}

func NewScanContextError(msg, scanID string) *RedTeamError {
	errorMsg := fmt.Sprintf(
		"Scan ID: %s failed. %s",
		scanID,
		msg,
	)
	return newRedTeamError(snyk_common_errors.NewBadRequestError(errorMsg), msg)
}

func NewScanNetworkError(msg, scanID string) *RedTeamError {
	errorMsg := fmt.Sprintf(
		"Scan ID: %s failed. We have issues reaching your target. Here are the details: %s",
		scanID,
		msg,
	)
	return newRedTeamError(snyk_common_errors.NewBadRequestError(errorMsg), msg)
}

func NewServerError(msg string) *RedTeamError {
	return newRedTeamError(snyk_common_errors.NewServerError(msg), msg)
}

func NewForbiddenError(msg string) *RedTeamError {
	return newRedTeamError(snyk_common_errors.NewUnauthorisedError(msg), msg)
}

func NewHTTPClientError(msg string) *RedTeamError {
	return newRedTeamError(cli_errors.NewGeneralCLIFailureError(msg), msg)
}

func NewPollingTimeoutError() *RedTeamError {
	msg := "We couldn't get the scan results in a reasonable time. Please try again or contact support."
	return newRedTeamError(snyk_common_errors.NewTimeoutError(msg), msg)
}

func NewGenericRedTeamError(msg string, err error) *RedTeamError {
	return newRedTeamError(err, msg)
}

func NewUnauthorizedError(msg string) *RedTeamError {
	return newRedTeamError(snyk_common_errors.NewUnauthorisedError(msg), msg)
}

func NewNotFoundError(msg string) *RedTeamError {
	return newRedTeamError(cli_errors.NewGeneralCLIFailureError(msg), msg)
}
