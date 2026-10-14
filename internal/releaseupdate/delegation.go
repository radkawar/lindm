// SPDX-License-Identifier: Apache-2.0

package releaseupdate

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"strings"

	"buf.build/go/protovalidate"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	updatev1 "lindm/gen/lindm/update/v1"
	"lindm/internal/pki"
)

const rolloutRole = "rollout"

func makeRolloutDelegation(root *metadata.Metadata[metadata.RootType], targets *metadata.Metadata[metadata.TargetsType], signers []signature.Signer) error {
	if len(signers) == 0 || len(signers) > 16 {
		return errors.New("releaseupdate: bounded rollout signing quorum required")
	}
	targets.Signed.Delegations = &metadata.Delegations{
		Keys:  make(map[string]*metadata.Key, len(signers)),
		Roles: []metadata.DelegatedRole{{Name: rolloutRole, Threshold: len(signers), Terminating: true, Paths: []string{"channels/*.json"}}},
	}
	for _, signer := range signers {
		if signer == nil {
			return errors.New("releaseupdate: nil rollout signer")
		}
		public, err := signer.PublicKey()
		if err != nil {
			return err
		}
		key, err := metadata.KeyFromPublicKey(public)
		if err != nil {
			return err
		}
		if err = targets.Signed.AddKey(key, rolloutRole); err != nil {
			return err
		}
	}
	return validateRolloutDelegation(root, targets)
}

// The supported graph is exactly root -> targets -> rollout, with a single
// terminating channels-only edge. Online keys cannot shadow package authority.
func validateRolloutDelegation(root *metadata.Metadata[metadata.RootType], targets *metadata.Metadata[metadata.TargetsType]) error {
	delegation := targets.Signed.Delegations
	if delegation == nil || delegation.SuccinctRoles != nil || len(delegation.Roles) != 1 || len(delegation.Keys) > 16 {
		return errors.New("releaseupdate: exactly one bounded rollout delegation required")
	}
	role := delegation.Roles[0]
	if role.Name != rolloutRole || !role.Terminating || len(role.Paths) != 1 || role.Paths[0] != "channels/*.json" || len(role.PathHashPrefixes) != 0 || role.Threshold < 1 || role.Threshold > len(role.KeyIDs) || len(role.KeyIDs) != len(delegation.Keys) {
		return errors.New("releaseupdate: rollout scope or quorum invalid")
	}
	for name := range targets.Signed.Targets {
		if strings.HasPrefix(name, "channels/") {
			return errors.New("releaseupdate: channel shadows delegated rollout authority")
		}
	}
	rootKeys := make(map[[32]byte]bool, len(root.Signed.Keys))
	for _, key := range root.Signed.Keys {
		if key == nil {
			return errors.New("releaseupdate: nil root key")
		}
		public, err := key.ToPublicKey()
		if err != nil {
			return err
		}
		der, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			return err
		}
		rootKeys[sha256.Sum256(der)] = true
	}
	unique := make(map[[32]byte]bool, len(role.KeyIDs))
	for _, id := range role.KeyIDs {
		key := delegation.Keys[id]
		if key == nil {
			return errors.New("releaseupdate: missing rollout key")
		}
		keyID, err := key.ID()
		if err != nil || keyID != id {
			return errors.New("releaseupdate: rollout key identity mismatch")
		}
		public, err := key.ToPublicKey()
		if err != nil {
			return err
		}
		if err = pki.ValidatePublicKey(public); err != nil {
			return err
		}
		der, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(der)
		if rootKeys[digest] {
			return errors.New("releaseupdate: rollout and offline/top-level role key reuse refused")
		}
		unique[digest] = true
	}
	if len(unique) < role.Threshold {
		return errors.New("releaseupdate: duplicate rollout quorum keys")
	}
	return nil
}

func validateRolloutTargets(rollout *metadata.Metadata[metadata.TargetsType]) error {
	if rollout == nil || rollout.Signed.Delegations != nil || len(rollout.Signed.Targets) > 128 {
		return errors.New("releaseupdate: invalid rollout metadata graph")
	}
	for name, info := range rollout.Signed.Targets {
		ring, ok := strings.CutPrefix(name, "channels/")
		if !ok || strings.Contains(ring, "/") || !strings.HasSuffix(ring, ".json") || !safeTargetPath(name) {
			return errors.New("releaseupdate: rollout attempted to authorize non-channel target")
		}
		if info == nil {
			return errors.New("releaseupdate: nil rollout target")
		}
		info.Path = name
		if err := validTarget(info, MaxCatalogBytes); err != nil {
			return err
		}
	}
	return nil
}

func validateOfflineArtifacts(validator protovalidate.Validator, targets *metadata.Metadata[metadata.TargetsType], channel *updatev1.AgentUpdateChannel) error {
	for _, artifact := range channel.GetArtifacts() {
		info := targets.Signed.Targets[artifact.GetTargetPath()]
		if info == nil || info.Custom == nil || len(*info.Custom) > 16384 {
			return errors.New("releaseupdate: package lacks offline release authorization")
		}
		info.Path = artifact.GetTargetPath()
		if err := validTarget(info, MaxTargetBytes); err != nil {
			return err
		}
		offline := new(updatev1.AgentUpdateArtifact)
		if err := protojson.Unmarshal(*info.Custom, offline); err != nil {
			return err
		}
		if err := validator.Validate(offline); err != nil {
			return err
		}
		if !proto.Equal(offline, artifact) {
			return errors.New("releaseupdate: online channel changed offline release identity or compatibility")
		}
		if name := artifact.GetSignatureTargetPath(); name != "" {
			signature := targets.Signed.Targets[name]
			if signature == nil {
				return errors.New("releaseupdate: native signature lacks offline authorization")
			}
			signature.Path = name
			if err := validTarget(signature, MaxSignatureBytes); err != nil {
				return err
			}
		}
	}
	return nil
}
