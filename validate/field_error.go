package validate

import (
	"errors"
	"fmt"

	"github.com/opencontainers/runtime-tools/specerror"
)

// FieldError wraps a specerror.Error with the JSON-style path of the
// configuration field that triggered it (for example
// "linux.mounts[2].destination"). The wrapped error keeps its stable
// specerror.Code and RFC 2119 reference, while the field path gives
// consumers a machine-locatable anchor without parsing free text.
type FieldError struct {
	// Field is the JSON-style path of the offending field.
	Field string

	// Err is the underlying spec violation, carrying the stable Code.
	Err error
}

// Error implements error. The field path is rendered as a prefix so the
// error stays readable when surfaced through multierror.
func (e *FieldError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Err.Error())
}

// Unwrap exposes the underlying error to errors.Is/errors.As.
func (e *FieldError) Unwrap() error {
	return e.Err
}

// Code returns the stable specerror.Code of the underlying violation.
func (e *FieldError) Code() specerror.Code {
	var rfcErr *specerror.Error
	if errors.As(e.Err, &rfcErr) {
		return rfcErr.Code
	}
	return specerror.NonRFCError
}

// newFieldError builds a FieldError from a stable specerror code.
func newFieldError(field string, code specerror.Code, detail string, version string) *FieldError {
	return &FieldError{
		Field: field,
		Err:   specerror.NewError(code, fmt.Errorf("%s", detail), version),
	}
}
