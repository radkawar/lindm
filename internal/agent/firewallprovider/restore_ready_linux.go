// SPDX-License-Identifier: Apache-2.0

//go:build linux

package firewallprovider

import resourcev1 "lindm/gen/lindm/resource/v1"

// RestoreReady reports whether the packaged lindm-firewall-restore.service,
// its root-protected binary and state directory, and its network-pre.target
// enable link are in custody: the same check every firewall observation
// reports as persistent_ready. It observes the host afresh on every call.
func RestoreReady() bool {
	return persistenceReady(&resourcev1.ResourceObservation{Metadata: &resourcev1.ObservationMetadata{}})
}
