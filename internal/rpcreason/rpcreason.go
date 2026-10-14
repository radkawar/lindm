// SPDX-License-Identifier: Apache-2.0

// Package rpcreason owns the Lindm-Reason Connect metadata key: the stable,
// machine-readable reason every lindm RPC denial carries next to its Connect
// code. Servers build denials with Error (or Set on a richer error); clients
// and harnesses read them with Get. Nothing else may spell the header name.
//
// Non-goals: reason vocabularies stay with the services that emit them, and
// this package does not map domain errors to codes.
package rpcreason

import (
	"errors"

	"connectrpc.com/connect"
)

// Header is the Connect metadata key carrying the reason.
const Header = "Lindm-Reason"

// Error returns a Connect error whose message and Lindm-Reason are both
// reason.
func Error(code connect.Code, reason string) *connect.Error {
	err := connect.NewError(code, errors.New(reason))
	Set(err, reason)
	return err
}

// Set records reason on err.
func Set(err *connect.Error, reason string) {
	err.Meta().Set(Header, reason)
}

// Get returns the reason carried by err, or "" when err is not a Connect
// error or carries none.
func Get(err error) string {
	var rpc *connect.Error
	if errors.As(err, &rpc) {
		return rpc.Meta().Get(Header)
	}
	return ""
}
