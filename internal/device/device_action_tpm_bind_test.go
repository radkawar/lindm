// SPDX-License-Identifier: Apache-2.0

package device

import (
	"testing"

	"lindm/internal/device/core"

	agentv1 "lindm/gen/lindm/agent/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/device/devicedb"
)

// The server refuses TPM2 binding before signing on releases whose shipped
// systemd-cryptenroll predates descriptor unlock (Ubuntu 22.04, systemd 249);
// an unobserved identity defers to the root provider's native probe.
func TestTPM2BindRefusedFromObservedRelease(t *testing.T) {
	success := int16(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS)
	denied := int16(inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED)
	for name, test := range map[string]struct {
		host devicedb.GetHostObservationRow
		want bool
	}{
		"jammy":               {devicedb.GetHostObservationRow{OsIDStatus: success, OsIDValue: "ubuntu", OsVersionStatus: success, OsVersionValue: "22.04"}, false},
		"noble":               {devicedb.GetHostObservationRow{OsIDStatus: success, OsIDValue: "ubuntu", OsVersionStatus: success, OsVersionValue: "24.04"}, true},
		"bookworm":            {devicedb.GetHostObservationRow{OsIDStatus: success, OsIDValue: "debian", OsVersionStatus: success, OsVersionValue: "12"}, true},
		"identity unobserved": {devicedb.GetHostObservationRow{OsIDStatus: denied, OsIDValue: "ubuntu", OsVersionStatus: success, OsVersionValue: "22.04"}, true},
		"version unobserved":  {devicedb.GetHostObservationRow{OsIDStatus: success, OsIDValue: "ubuntu", OsVersionStatus: denied, OsVersionValue: "22.04"}, true},
	} {
		if got := core.TPM2BindSupported(test.host); got != test.want {
			t.Errorf("%s: tpm2BindSupported = %t, want %t", name, got, test.want)
		}
	}
}

// Encryption status compares the bound keyslot's identical systemd-tpm2
// token references with what the observed release needs (4 where its
// systemd's PCR_CHANGED retry is broken); an unobserved release needs 0.
func TestTPM2TokenReferenceStatus(t *testing.T) {
	success := int16(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS)
	denied := int16(inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED)
	absent := int16(inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE)
	for name, test := range map[string]struct {
		host devicedb.GetHostObservationRow
		want uint32
	}{
		"noble":      {devicedb.GetHostObservationRow{OsIDStatus: success, OsIDValue: "ubuntu", OsVersionStatus: success, OsVersionValue: "24.04"}, 4},
		"rhel 9":     {devicedb.GetHostObservationRow{OsIDStatus: success, OsIDValue: "rhel", OsVersionStatus: success, OsVersionValue: "9.8"}, 4},
		"bookworm":   {devicedb.GetHostObservationRow{OsIDStatus: success, OsIDValue: "debian", OsVersionStatus: success, OsVersionValue: "12"}, 1},
		"unobserved": {devicedb.GetHostObservationRow{OsIDStatus: denied, OsIDValue: "ubuntu", OsVersionStatus: success, OsVersionValue: "24.04"}, 0},
		// Official Arch has no VERSION_ID; its native absence identifies it.
		"arch":                 {devicedb.GetHostObservationRow{OsIDStatus: success, OsIDValue: "arch", OsVersionStatus: absent}, 1},
		"versioned no version": {devicedb.GetHostObservationRow{OsIDStatus: success, OsIDValue: "ubuntu", OsVersionStatus: absent}, 0},
	} {
		if got := core.TPM2TokenReferencesRequired(test.host); got != test.want {
			t.Errorf("%s: required references = %d, want %d", name, got, test.want)
		}
	}
	token := func(id uint32, kind string, slots ...uint32) *agentv1.LUKSTokenObservation {
		return &agentv1.LUKSTokenObservation{TokenId: id, Type: kind, Keyslots: slots}
	}
	for name, test := range map[string]struct {
		tokens []*agentv1.LUKSTokenObservation
		want   uint32
	}{
		"unbound":   {[]*agentv1.LUKSTokenObservation{token(0, "lindm-recovery", 2)}, 0},
		"legacy":    {[]*agentv1.LUKSTokenObservation{token(0, "lindm-recovery", 2), token(1, "systemd-tpm2", 1)}, 1},
		"complete":  {[]*agentv1.LUKSTokenObservation{token(0, "systemd-tpm2", 1), token(1, "systemd-tpm2", 1), token(2, "systemd-tpm2", 1), token(3, "systemd-tpm2", 1)}, 4},
		"two binds": {[]*agentv1.LUKSTokenObservation{token(0, "systemd-tpm2", 1), token(1, "systemd-tpm2", 3), token(2, "systemd-tpm2", 3)}, 2},
		"multi":     {[]*agentv1.LUKSTokenObservation{token(0, "systemd-tpm2", 1, 3)}, 0},
	} {
		if got := core.TPM2TokenReferences(&agentv1.DeviceActionObservation{LuksTokens: test.tokens}); got != test.want {
			t.Errorf("%s: references = %d, want %d", name, got, test.want)
		}
	}
}
