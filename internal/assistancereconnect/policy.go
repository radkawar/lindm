// SPDX-License-Identifier: Apache-2.0

// Package assistancereconnect holds the reconnect-workflow bounds shared by the
// server, root broker and session helper. A workflow remembers only bounded
// metadata; it never carries a grant, portal token, relay or DTLS identity.
package assistancereconnect

import (
	agentv1 "lindm/gen/lindm/agent/v1"
)

const (
	MinWindowSeconds = 60
	MaxWindowSeconds = 4 * 60 * 60
	MaxReconnects    = 8
)

// Intersect is the stricter of two reconnect bounds. An absent side never
// enables reconnect.
func Intersect(a, b *agentv1.AssistanceReconnectPolicy) *agentv1.AssistanceReconnectPolicy {
	if a.GetWindowSeconds() < MinWindowSeconds || b.GetWindowSeconds() < MinWindowSeconds || a.GetMaxReconnects() == 0 || b.GetMaxReconnects() == 0 {
		return nil
	}
	return &agentv1.AssistanceReconnectPolicy{
		WindowSeconds: min(a.GetWindowSeconds(), b.GetWindowSeconds(), MaxWindowSeconds),
		MaxReconnects: min(a.GetMaxReconnects(), b.GetMaxReconnects(), MaxReconnects),
	}
}
