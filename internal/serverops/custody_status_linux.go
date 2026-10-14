// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"errors"
	"os"
)

// CustodyStatus prints no secret material. The explicit original configuration
// binding prevents a global host record from confirming a different deployment.
func CustodyStatus(configPath string) (health RecoveryCustodyHealth, err error) {
	if os.Geteuid() != 0 {
		return health, errors.New("operations: root_required")
	}
	stage, err := offlineStage("lindmd-custody-status-*")
	if err != nil {
		return health, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(stage)) }()
	resources, err := newResources(configPath, stage)
	if err != nil {
		return health, err
	}
	expected, err := NewBackupIdentity(resources.config)
	if err != nil {
		return health, err
	}
	health, err = ReadRecoveryCustodyHealth(RecoveryCustodyHealthPath)
	if err != nil {
		return health, err
	}
	if !RecoveryCustodyHealthMatches(health, expected) {
		return RecoveryCustodyHealth{}, errors.New("operations: custody_configuration_binding_mismatch")
	}
	return health, nil
}
