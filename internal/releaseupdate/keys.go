// SPDX-License-Identifier: Apache-2.0

package releaseupdate

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"github.com/theupdateframework/go-tuf/v2/metadata"

	"lindm/internal/pki"
)

type RoleSigners struct{ Root, Targets, Rollout, Snapshot, Timestamp []signature.Signer }

func (s RoleSigners) roles() map[string][]signature.Signer {
	return map[string][]signature.Signer{"root": s.Root, "targets": s.Targets, "rollout": s.Rollout, "snapshot": s.Snapshot, "timestamp": s.Timestamp}
}

func validateRoot(root *metadata.Metadata[metadata.RootType]) error {
	if root == nil || root.Signed.Type != metadata.ROOT || root.Signed.Version < 1 || !root.Signed.ConsistentSnapshot {
		return errors.New("releaseupdate: consistent root required")
	}
	seen := map[[32]byte]string{}
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		definition := root.Signed.Roles[role]
		if definition == nil || definition.Threshold < 1 || definition.Threshold > len(definition.KeyIDs) {
			return errors.New("releaseupdate: invalid role quorum")
		}
		unique := map[[32]byte]bool{}
		for _, id := range definition.KeyIDs {
			key := root.Signed.Keys[id]
			if key == nil {
				return errors.New("releaseupdate: missing role key")
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
			if previous, ok := seen[digest]; ok && previous != role {
				return errors.New("releaseupdate: role key reuse refused")
			}
			seen[digest] = role
			unique[digest] = true
		}
		if len(unique) < definition.Threshold {
			return errors.New("releaseupdate: duplicate quorum keys")
		}
	}
	return nil
}

func validateSigners(root *metadata.Metadata[metadata.RootType], signers RoleSigners) error {
	for role, keys := range signers.roles() {
		if role == rolloutRole || ((role == metadata.ROOT || role == metadata.TARGETS) && len(keys) == 0) {
			continue
		}
		definition := root.Signed.Roles[role]
		if err := validateRoleSigners(definition.KeyIDs, definition.Threshold, keys); err != nil {
			return err
		}
	}
	return nil
}

func validateRoleSigners(ids []string, threshold int, signers []signature.Signer) error {
	unique := make(map[string]bool, len(signers))
	for _, signer := range signers {
		if signer == nil {
			return errors.New("releaseupdate: nil role signer")
		}
		public, err := signer.PublicKey()
		if err != nil {
			return err
		}
		key, err := metadata.KeyFromPublicKey(public)
		if err != nil {
			return err
		}
		id, err := key.ID()
		if err != nil {
			return err
		}
		authorized := false
		for _, allowed := range ids {
			if id == allowed {
				authorized = true
				break
			}
		}
		if !authorized {
			return errors.New("releaseupdate: unauthorized role signer")
		}
		unique[id] = true
	}
	if len(unique) < threshold {
		return errors.New("releaseupdate: insufficient role signing custody")
	}
	return nil
}

// LoadRoleSigners loads explicit PKCS8 custody. There is no ambient key lookup,
// development fallback or private key storage in the served repository.
func LoadRoleSigners(directory string, includeRoot bool) (RoleSigners, error) {
	roles := []string{"targets", rolloutRole, "snapshot", "timestamp"}
	if includeRoot {
		roles = append(roles, "root")
	}
	return loadRoleSigners(directory, roles, false)
}

// LoadOnlineSigners rejects offline private custody instead of merely choosing
// not to read it. A server can change rollout policy, never release authority.
func LoadOnlineSigners(directory string) (RoleSigners, error) {
	return loadRoleSigners(directory, []string{rolloutRole, "snapshot", "timestamp"}, true)
}

func loadRoleSigners(directory string, roles []string, online bool) (result RoleSigners, err error) {
	if err = ownedDirectory(directory); err != nil {
		return result, err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	if online {
		for _, name := range []string{"root.pem", "targets.pem"} {
			if _, statErr := root.Lstat(name); !errors.Is(statErr, os.ErrNotExist) {
				return result, errors.New("releaseupdate: offline private custody exposed to online publisher")
			}
		}
	}
	for _, role := range roles {
		file, err := openRegular(root, role+".pem")
		if err != nil {
			return result, err
		}
		st, statErr := file.Stat()
		closeErr := file.Close()
		if statErr != nil || closeErr != nil {
			return result, errors.Join(statErr, closeErr)
		}
		if st.Mode().Perm() != 0600 {
			return result, errors.New("releaseupdate: signing key must have mode 0600")
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Geteuid()) {
			return result, errors.New("releaseupdate: signing key owner mismatch")
		}
		data, err := readBounded(root, role+".pem", 65536)
		if err != nil {
			return result, err
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
			return result, errors.New("releaseupdate: PKCS8 private key required")
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return result, err
		}
		var signer signature.Signer
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			signer, err = signature.LoadSignerWithOpts(rsaKey, options.WithRSAPSS(&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}))
		} else {
			signer, err = signature.LoadSignerWithOpts(key)
		}
		if err != nil {
			return result, err
		}
		switch role {
		case "root":
			result.Root = []signature.Signer{signer}
		case "targets":
			result.Targets = []signature.Signer{signer}
		case rolloutRole:
			result.Rollout = []signature.Signer{signer}
		case "snapshot":
			result.Snapshot = []signature.Signer{signer}
		case "timestamp":
			result.Timestamp = []signature.Signer{signer}
		}
	}
	return result, nil
}

// GenerateDevelopmentKeys creates conspicuously opt-in local test custody only.
// Existing keys are never replaced. Production custody must be provisioned separately.
func GenerateDevelopmentKeys(directory string) (err error) {
	if err = ownedDirectory(directory); err != nil {
		return err
	}
	for _, role := range []string{"root", "targets", rolloutRole, "snapshot", "timestamp"} {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(filepath.Join(directory, role+".pem"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, writeErr := f.Write(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
		syncErr := f.Sync()
		closeErr := f.Close()
		if err = errors.Join(writeErr, syncErr, closeErr); err != nil {
			return err
		}
	}
	return syncDir(directory)
}
