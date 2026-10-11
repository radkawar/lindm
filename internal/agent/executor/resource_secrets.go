//go:build linux

package executor

import (
	"bytes"
	"context"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/resource"
	"lindm/internal/secretseal"
)

// secretAccessor opens one delivered SecretRef for a single native use. The
// caller secretseal.Clears the result as soon as that use ends. Providers
// receive it from the executor; nothing else can request delivered material.
type secretAccessor func(context.Context, *resourcev1.SecretRef) (*agentv1.SecretMaterial, error)

// verifyResourceSecrets authenticates sealed deliveries before any native use.
// The expected binding is rebuilt from the verified intent and this executor's
// own identity, so neither the relay nor a reordered manifest can rebind
// ciphertext to another device, action, resource or secret version. Each
// delivery is opened once to prove it is decryptable here, then cleared.
// The caller holds s.mu and passes state from s.enrolled.
func (s *Service) verifyResourceSecrets(loaded *bound, intent *agentv1.ResourceExecutionIntent, sealed [][]byte) error {
	refs, err := resource.SecretRefs(intent.GetDesired(), intent.GetOperation())
	if err != nil {
		return errSecretDeliveryRejected
	}
	deliveries := intent.GetSecrets()
	if len(deliveries) != len(refs) || len(sealed) != len(deliveries) {
		return errSecretDeliveryRejected
	}
	for i, delivery := range deliveries {
		binding := delivery.GetBinding()
		expected := &agentv1.SecretDeliveryBinding{
			DeploymentId: loaded.bootstrap.Root.GetDeploymentId(), DeviceId: loaded.state.GetDeviceId(),
			EnrollmentGeneration: loaded.state.GetEnrollmentGeneration(), ActionId: intent.GetActionId(),
			Resource: intent.GetDesired().GetRef(), Secret: refs[i],
			// openSecretDelivery accepts only this executor's current or retained key.
			RecipientKeySha256: binding.GetRecipientKeySha256(),
		}
		if !proto.Equal(expected, binding) || !bytes.Equal(digestBytes(sealed[i]), delivery.GetSealedSha256()) {
			return errSecretDeliveryRejected
		}
		material, err := s.openSecretDelivery(loaded, binding, sealed[i])
		if err != nil {
			return err
		}
		secretseal.Clear(material)
	}
	return nil
}

// sameResourceSecrets reports whether a retried preparation carries exactly the
// deliveries the signed intent of an existing record authenticated. Journaled
// bytes are compared too while the record still retains them.
func sameResourceSecrets(record *agentv1.ResourceExecutionRecord, sealed [][]byte) bool {
	deliveries := record.GetIntent().GetSecrets()
	if len(sealed) != len(deliveries) {
		return false
	}
	retained := record.GetSealedSecrets()
	for i, delivery := range deliveries {
		if !bytes.Equal(digestBytes(sealed[i]), delivery.GetSealedSha256()) || (len(retained) != 0 && !bytes.Equal(retained[i], sealed[i])) {
			return false
		}
	}
	return true
}

// resourceSecrets returns the accessor for one action's authenticated sealed
// deliveries. Every call reopens the ciphertext under the authority lock, so
// plaintext lives only for the provider's single use.
func (s *Service) resourceSecrets(intent *agentv1.ResourceExecutionIntent, sealed [][]byte) secretAccessor {
	deliveries := intent.GetSecrets()
	retained := make([][]byte, len(sealed))
	for i := range sealed {
		retained[i] = bytes.Clone(sealed[i])
	}
	return func(ctx context.Context, ref *resourcev1.SecretRef) (*agentv1.SecretMaterial, error) {
		for i, delivery := range deliveries {
			if !proto.Equal(delivery.GetBinding().GetSecret(), ref) {
				continue
			}
			if i >= len(retained) || !bytes.Equal(digestBytes(retained[i]), delivery.GetSealedSha256()) {
				return nil, errSecretDeliveryRejected
			}
			if err := s.lock(ctx); err != nil {
				return nil, err
			}
			defer s.mu.Unlock()
			loaded, err := s.enrolled(ctx)
			if err != nil {
				return nil, err
			}
			return s.openSecretDelivery(loaded, delivery.GetBinding(), retained[i])
		}
		return nil, errSecretDeliveryRejected
	}
}

// validateRetainedSecrets keeps journaled ciphertext bound to the signed
// manifest and absent from terminal records.
func validateRetainedSecrets(record *agentv1.ResourceExecutionRecord) bool {
	sealed := record.GetSealedSecrets()
	if len(sealed) == 0 {
		return true
	}
	if record.GetCompletedAt() != nil {
		return false
	}
	return sameResourceSecrets(record, sealed)
}
