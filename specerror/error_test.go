package specerror

import (
	"errors"
	"testing"

	"github.com/hashicorp/go-multierror"
)

type wrappedCodeError struct {
	code Code
	err  error
}

func (e *wrappedCodeError) Error() string {
	return e.err.Error()
}

func (e *wrappedCodeError) Unwrap() error {
	return e.err
}

func (e *wrappedCodeError) Code() Code {
	return e.code
}

func TestFindErrorWithWrappedCode(t *testing.T) {
	inner := NewError(NSPathAbs, errors.New("bad namespace path"), "1.3.0")
	wrapped := &wrappedCodeError{code: NSPathAbs, err: inner}

	var merr *multierror.Error
	merr = multierror.Append(merr, wrapped)

	if got := FindError(merr, NSPathAbs); got != NSPathAbs {
		t.Fatalf("expected FindError to see wrapped code %v, got %v", NSPathAbs, got)
	}
	if got := FindError(merr, NSErrorOnDup); got != NonRFCError {
		t.Fatalf("expected non-matching code to return NonRFCError, got %v", got)
	}
}

func TestFindErrorDirectError(t *testing.T) {
	inner := NewError(MaskedPathsAbs, errors.New("bad masked path"), "1.3.0")

	var merr *multierror.Error
	merr = multierror.Append(merr, inner)

	if got := FindError(merr, MaskedPathsAbs); got != MaskedPathsAbs {
		t.Fatalf("expected FindError to see code %v, got %v", MaskedPathsAbs, got)
	}
}
