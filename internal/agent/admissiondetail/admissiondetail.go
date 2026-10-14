// SPDX-License-Identifier: Apache-2.0

// Package admissiondetail attaches a closed, actionable snake_case detail code
// to a provider refusal without changing its sentinel classification.
package admissiondetail

import "errors"

const maxDetailLength = 64

// Wrap returns err annotated with detail. errors.Is/As see through the
// wrapper. A nil err or a detail that is not ^[a-z][a-z0-9_]{0,63}$ returns
// err unchanged.
func Wrap(err error, detail string) error {
	if err == nil || !valid(detail) {
		return err
	}
	return &detailError{err: err, detail: detail}
}

// Of returns the outermost detail in err's chain, or "" when none is present.
func Of(err error) string {
	var target *detailError
	if errors.As(err, &target) {
		return target.detail
	}
	return ""
}

type detailError struct {
	err    error
	detail string
}

func (e *detailError) Error() string { return e.err.Error() }
func (e *detailError) Unwrap() error { return e.err }

func valid(detail string) bool {
	if len(detail) == 0 || len(detail) > maxDetailLength {
		return false
	}
	if detail[0] < 'a' || detail[0] > 'z' {
		return false
	}
	for i := 1; i < len(detail); i++ {
		c := detail[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}
