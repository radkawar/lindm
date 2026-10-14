// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"errors"
	"os"
	"path/filepath"

	"lindm/internal/config"
)

func (r *resourceSet) migrationInventory(path string) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := r.copy(path); err != nil {
		return err
	}
	document, err := config.Load(r.files[path])
	if err != nil {
		return errors.New("operations: invalid_migration_configuration")
	}
	previousBase := r.base
	r.base = filepath.Dir(path)
	defer func() { r.base = previousBase }()
	if err = r.inventory(document.Proto.ProtoReflect()); err != nil {
		return err
	}
	for _, credential := range []string{document.Proto.GetDatabase().GetUrlFile(), document.Proto.GetDatabase().GetMigrationUrlFile()} {
		if credential != "" {
			if _, err = r.database(credential); err != nil {
				return err
			}
			if err = r.copy(r.reference(credential)); err != nil {
				return err
			}
		}
	}
	return r.rewrite(document.Proto.ProtoReflect())
}
