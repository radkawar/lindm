//go:build linux

package packaging

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestSessionHelperIsAPackagedUserUnit(t *testing.T) {
	product := agentProduct()
	if !slices.Contains(product.userUnits, sessionUnit) || slices.Contains(product.units, sessionUnit) {
		t.Fatal("session helper must be verified as a user unit, not a system unit")
	}
	files, err := product.payloadFiles()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, file := range files {
		if file.name == sessionUnit {
			found = file.rel == "usr/lib/systemd/user/"+sessionUnit && file.mode == 0o644 && !file.conf
		}
	}
	if !found {
		t.Fatal("session helper omitted from the user unit directory")
	}
}

func TestPackagedUnitsVerifyInTheirManagerScope(t *testing.T) {
	requireNativeTools(t, "systemd-analyze")
	work := t.TempDir()
	if err := os.Mkdir(filepath.Join(work, "tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	ok, _, err := verifyUnits(context.Background(), work, agentProduct())
	if err != nil || !ok {
		t.Fatalf("agent system and user units: ok=%v err=%v", ok, err)
	}
	if _, err := os.Stat(filepath.Join(work, "units-user", sessionUnit)); err != nil {
		t.Fatalf("user unit was not verified: %v", err)
	}
}
