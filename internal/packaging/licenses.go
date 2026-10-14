// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packaging

// LicenseNames lists the redistribution texts installed by every product.
func LicenseNames() [3]string {
	return [3]string{"LICENSE", "NOTICE", "THIRD-PARTY-LICENSES"}
}
