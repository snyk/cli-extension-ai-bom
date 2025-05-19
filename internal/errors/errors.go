package errors

import (
	aibom_errors "github.com/snyk/error-catalog-golang-public/aibom"
	cli_errors "github.com/snyk/error-catalog-golang-public/cli"
	snyk_common_errors "github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

// AiBomError is a wrapper around snyk_errors to abstract & enable greater control of errors within this repository.
type AiBomError struct {
	SnykError snyk_errors.Error
}

func NewForbiddenError(msg string) *AiBomError {
	return &AiBomError{SnykError: aibom_errors.NewForbiddenError(msg)}
}

func NewUnauthorizedError(msg string) *AiBomError {
	return &AiBomError{SnykError: snyk_common_errors.NewUnauthorisedError(msg)}
}

func NewInternalError(msg string) *AiBomError {
	return &AiBomError{SnykError: aibom_errors.NewInternalError(msg)}
}

func NewNoSupportedFilesError(msg string) *AiBomError {
	return &AiBomError{SnykError: aibom_errors.NewNoSupportedFilesError(msg)}
}

func NewCommandIsExperimentalError() *AiBomError {
	return &AiBomError{SnykError: cli_errors.NewCommandIsExperimentalError("snyk aibom is experimental and likely to change")}
}
