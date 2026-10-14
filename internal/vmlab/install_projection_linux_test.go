// SPDX-License-Identifier: Apache-2.0

package vmlab

import (
	"context"
	"errors"
	"os"
	"testing"

	"lindm/internal/agent/statefs"
)

func TestInstallProjectionRejectsReplaceableFixtureParent(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0777); err != nil {
		t.Fatal(err)
	}
	result, err := CheckInstallProjection(context.Background(), parent)
	if !errors.Is(err, statefs.ErrUnsafe) || result != nil {
		t.Fatalf("replaceable fixture parent must be rejected before native execution: result=%v err=%v", result, err)
	}
}
