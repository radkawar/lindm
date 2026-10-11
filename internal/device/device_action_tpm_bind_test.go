package device

import (
	"testing"

	"lindm/internal/device/core"

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
