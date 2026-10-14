// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"errors"
	"os"

	"lindm/internal/config"
)

// StageConfig validates a private native configuration and copies its admitted
// resources into a root-owned temporary tree. The original loader's ownership,
// credential and TLS checks remain unchanged. Cleanup must be called on every
// successful return; the document must not outlive cleanup.
func StageConfig(path string) (*config.Document, func() error, error) {
	if os.Geteuid() != 0 {
		return nil, nil, errors.New("operations: root_required")
	}
	stage, err := os.MkdirTemp("/run", "lindmd-operations-*")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() error { return os.RemoveAll(stage) }
	resources, err := newResources(path, stage)
	if err != nil {
		return nil, nil, errors.Join(err, cleanup())
	}
	document, err := resources.validate(path)
	if err != nil {
		return nil, nil, errors.Join(err, cleanup())
	}
	return document, cleanup, nil
}
