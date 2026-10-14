// SPDX-License-Identifier: Apache-2.0

package identity

import "crypto/subtle"

func hashesDiffer(a, b []byte) bool {
	if len(a) != len(b) {
		return true
	}
	return subtle.ConstantTimeCompare(a, b) != 1
}
