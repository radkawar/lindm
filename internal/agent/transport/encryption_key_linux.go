// SPDX-License-Identifier: Apache-2.0

//go:build linux

package transport

import (
	"bytes"
	"context"
	"errors"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
)

// registerEncryptionKey relays the root's identity-signed HPKE recipient key to
// the server once per certificate. Once the root reports the key acknowledged
// under the connection's certificate, later cycles make no call at all; a
// renewal changes the certificate and so registers the successor key.
func (m *managementLoop) registerEncryptionKey(ctx context.Context, connection *agentv1.GetConnectionResponse) error {
	certificate := connection.GetCertificateSha256()
	if len(certificate) == 0 || bytes.Equal(m.encryptionKeyCertificate, certificate) {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	// Hold the authority gate so no renewal interleaves between attestation,
	// registration and acknowledgment.
	if err := m.gate.lock(ctx); err != nil {
		return err
	}
	defer m.gate.unlock()
	authority, err := establishLocked(ctx, m.executor, &m.cache)
	if err != nil {
		return err
	}
	prepared, err := rpc(ctx, m.executor.PrepareEncryptionKey, &agentv1.PrepareEncryptionKeyRequest{})
	if err != nil {
		return err
	}
	if !prepared.GetAcknowledged() {
		registered, err := rpc(ctx, authority.servers.device.RegisterEncryptionKey, &devicev1.RegisterEncryptionKeyRequest{SessionEpoch: authority.epoch, AttestationEnvelope: prepared.GetAttestationEnvelope()})
		if err != nil {
			return err
		}
		if !bytes.Equal(registered.GetPublicKeySha256(), prepared.GetPublicKeySha256()) || !bytes.Equal(registered.GetCertificateSha256(), prepared.GetCertificateSha256()) {
			return errors.New("server registered a different encryption key or certificate")
		}
		if _, err := rpc(ctx, m.executor.AcknowledgeEncryptionKey, &agentv1.AcknowledgeEncryptionKeyRequest{PublicKeySha256: prepared.GetPublicKeySha256(), CertificateSha256: prepared.GetCertificateSha256()}); err != nil {
			return err
		}
	}
	m.encryptionKeyCertificate = bytes.Clone(prepared.GetCertificateSha256())
	return nil
}
