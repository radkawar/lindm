// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"

	"lindm/internal/assistancerecording"
)

// assistanceRecording loads the deployment recording recipient: exactly 32
// CSPRNG bytes in an owner-only file distinct from the escrow keys.
func (d *Document) assistanceRecording() (*assistancerecording.Recipient, error) {
	cfg := d.Proto.GetAssistance().GetRecording()
	if cfg == nil {
		return nil, nil
	}
	path := reference(d.base, cfg.GetKeyFile())
	if escrow := d.Proto.GetEscrow(); escrow != nil {
		if path == reference(d.base, escrow.GetTransportKeyFile()) || path == reference(d.base, escrow.GetWrappingKeyFile()) {
			return nil, errors.New("assistance recording key must not share a file with escrow keys")
		}
	}
	seed, err := readFile(path, true)
	if err != nil {
		return nil, fmt.Errorf("read assistance.recording.key_file: %w", err)
	}
	defer clear(seed)
	recipient, err := assistancerecording.NewRecipient(seed)
	if err != nil {
		return nil, errors.New("assistance recording key must be exactly 32 random bytes")
	}
	return recipient, nil
}
