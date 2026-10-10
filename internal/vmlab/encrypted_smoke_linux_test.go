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

func TestEncryptedPostureDiagnosticRetainsReasonWithoutGuestPath(t *testing.T) {
	got := encryptedPostureDiagnostic([]byte("od: /private/owner-secret: No such file or directory\n"))
	want := "No such file or directory (guest paths and other stderr redacted)"
	if got != want {
		t.Fatalf("safe native diagnostic = %q, want %q", got, want)
	}
	if got := encryptedPostureDiagnostic([]byte("private enrollment secret")); got != "unclassified native failure (stderr bytes 25; private text withheld)" {
		t.Fatalf("unclassified diagnostic leaked text: %q", got)
	}
}
