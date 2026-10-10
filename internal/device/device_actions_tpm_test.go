package device

import (
	"testing"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// Regression: TPM2 binding was refused on every real TPM 2.0 device because
// the gate compared against "2.0" while the collector reports sysfs "2".
func TestTPM2AvailableMatchesCollectorVersion(t *testing.T) {
	ok := inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	denied := inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED
	tpm := func(presentStatus inventoryv1.CollectionStatus, present bool, versionStatus inventoryv1.CollectionStatus, version string) *inventoryv1.TpmDetails {
		return &inventoryv1.TpmDetails{
			Present: &inventoryv1.ObservedBool{Status: presentStatus, Value: present},
			Version: &inventoryv1.ObservedString{Status: versionStatus, Value: version},
		}
	}
	for name, test := range map[string]struct {
		tpm  *inventoryv1.TpmDetails
		want bool
	}{
		"collector TPM 2":        {tpm(ok, true, ok, "2"), true},
		"TPM 1.2 major version":  {tpm(ok, true, ok, "1"), false},
		"absent":                 {tpm(ok, false, ok, ""), false},
		"presence not observed":  {tpm(denied, true, ok, "2"), false},
		"version not observed":   {tpm(ok, true, denied, "2"), false},
		"missing inventory data": {nil, false},
	} {
		if got := tpm2Available(test.tpm); got != test.want {
			t.Errorf("%s: tpm2Available = %v, want %v", name, got, test.want)
		}
	}
}
