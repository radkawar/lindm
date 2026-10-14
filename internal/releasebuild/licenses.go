// SPDX-License-Identifier: Apache-2.0

package releasebuild

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// The authenticated, validated manifest admits exactly the three canonical
// redistribution documents. They are first-class signed payloads, not a claim
// inferred from a successful unsigned-package reproducibility comparison.
func verifyLicenseFiles(ctx context.Context, directory string, declared map[string]string) error {
	for name, expected := range declared {
		if err := ctx.Err(); err != nil {
			return err
		}
		path := filepath.Join(directory, name)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("releasebuild: license document link or special file refused")
		}
		sum, _, err := digestBoundedFile(path, maxDocument)
		if err != nil {
			return err
		}
		if sum != expected {
			return fmt.Errorf("releasebuild: signed license document digest mismatch: %s", name)
		}
	}
	return nil
}
