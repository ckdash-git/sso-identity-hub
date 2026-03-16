// Package errors defines sentinel error types used throughout the application.
// Using typed errors instead of strings allows callers to use errors.Is/As
// for precise branching without string matching.
package errors

import (
	"errors"
	"fmt"
	"net/http"
)

// Sentinel errors — compare with errors.Is.
var (
	ErrNotFound           = errors.New("resource not found")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrForbidden          = errors.New("forbidden")
	ErrConflict           = errors.New("resource conflict")
	ErrInvalidInput       = errors.New("invalid input")
	ErrInternal           = errors.New("internal server error")
	ErrSessionExpired     = errors.New("session expired")
	ErrSessionNotFound    = errors.New("session not found")
	ErrTokenExpired       = errors.New("token expired")
	ErrTokenInvalid       = errors.New("token invalid")
	ErrMFARequired        = errors.New("mfa required")
	ErrProvisioningFailed = errors.New("scim provisioning failed")
)

// AppError wraps a sentinel error with a human-readable message and an HTTP
// status code so that a single error value carries all information a handler needs.
type AppError struct {
	Sentinel error
	Message  string
	HTTPCode int
	Internal error // original low-level error, never exposed to clients
}

func (e *AppError) Error() string {
	if e.Internal != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Internal)
	}
	return e.Message
}

// Unwrap enables errors.Is/errors.As traversal through AppError chains.
func (e *AppError) Unwrap() error { return e.Sentinel }

// New constructs an AppError. Use the public helpers below for common cases.
func New(sentinel error, msg string, httpCode int, internal error) *AppError {
	return &AppError{
		Sentinel: sentinel,
		Message:  msg,
		HTTPCode: httpCode,
		Internal: internal,
	}
}

func NotFound(msg string, internal error) *AppError {
	return New(ErrNotFound, msg, http.StatusNotFound, internal)
}

func Unauthorized(msg string, internal error) *AppError {
	return New(ErrUnauthorized, msg, http.StatusUnauthorized, internal)
}

func Forbidden(msg string, internal error) *AppError {
	return New(ErrForbidden, msg, http.StatusForbidden, internal)
}

func Conflict(msg string, internal error) *AppError {
	return New(ErrConflict, msg, http.StatusConflict, internal)
}

func InvalidInput(msg string, internal error) *AppError {
	return New(ErrInvalidInput, msg, http.StatusBadRequest, internal)
}

func Internal(msg string, internal error) *AppError {
	return New(ErrInternal, msg, http.StatusInternalServerError, internal)
}

func SessionExpired(msg string) *AppError {
	return New(ErrSessionExpired, msg, http.StatusUnauthorized, nil)
}

func TokenInvalid(msg string, internal error) *AppError {
	return New(ErrTokenInvalid, msg, http.StatusUnauthorized, internal)
}

// HTTPCodeOf extracts the HTTP status code from an error chain.
// Defaults to 500 if no AppError is found in the chain.
func HTTPCodeOf(err error) int {
	var ae *AppError
	if errors.As(err, &ae) {
		return ae.HTTPCode
	}
	return http.StatusInternalServerError
}

// ClientMessage returns a safe message suitable for sending to API consumers.
// It never exposes the internal error detail.
func ClientMessage(err error) string {
	var ae *AppError
	if errors.As(err, &ae) {
		return ae.Message
	}
	return "internal server error"
}
