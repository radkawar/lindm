//go:build linux

package vmlab

import "testing"

func TestEncryptedSmokeFailureRecordsCompletion(t *testing.T) {
	t.Setenv("SUPERMIN_KERNEL", "")
	t.Setenv("SUPERMIN_MODULES", "")
	evidence, err := EncryptedSmoke(t.Context(), nil, EncryptedVMOptions{})
	if err == nil || evidence == nil || evidence.Failure == "" {
		t.Fatalf("missing explicit failed smoke evidence: %+v, %v", evidence, err)
	}
	if evidence.StartedAt.IsZero() || evidence.CompletedAt.IsZero() {
		t.Fatal("failed smoke omitted bounded observation timestamps")
	}
}
