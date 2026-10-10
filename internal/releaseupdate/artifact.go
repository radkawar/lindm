package releaseupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// ArtifactMetadata is an offline-targets-authorized descriptor. It does not
// attest that a native platform can execute the artifact.
type ArtifactMetadata struct {
	Length int64
	SHA256 []byte
}

// Artifact refreshes the pinned TUF chain, including durable rollback fences,
// and reads only offline-owned targets. Online rollout signatures cannot assert
// recovery image sizes or authorize a different recovery image.
func (c *Client) Artifact(ctx context.Context, name string) (result *ArtifactMetadata, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !safeTargetPath(name) || strings.HasPrefix(name, "channels/") {
		return nil, errors.New("releaseupdate: invalid artifact target")
	}
	lock, err := acquireLock(c.cfg.StateDir)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	state, err := c.loadState()
	if err != nil {
		return nil, err
	}
	update, err := c.refresh(ctx, state)
	if err != nil {
		return nil, err
	}
	info := update.GetTrustedMetadataSet().Targets[metadata.TARGETS].Signed.Targets[name]
	if info == nil {
		return nil, ErrNotFound
	}
	info.Path = name
	if err = validTarget(info, MaxTargetBytes); err != nil {
		return nil, err
	}
	return &ArtifactMetadata{Length: info.Length, SHA256: bytes.Clone(info.Hashes["sha256"])}, nil
}

// RecoveryTargetPath binds the lookup name to the exact hash in the signed
// destructive action. The descriptor's authenticated hash must still match.
func RecoveryTargetPath(digest []byte) (string, error) {
	if len(digest) != sha256.Size {
		return "", errors.New("releaseupdate: recovery digest required")
	}
	return "recovery/" + hex.EncodeToString(digest) + ".efi", nil
}

// PublishArtifact imports a bounded regular file and signs its exact streamed
// hash and length using offline targets custody. Channel publication is separate.
func (p *Publisher) PublishArtifact(ctx context.Context, name, source string) (err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !safeTargetPath(name) || strings.HasPrefix(name, "channels/") {
		return errors.New("releaseupdate: invalid artifact target")
	}
	if len(p.cfg.Signers.Targets) == 0 {
		return errors.New("releaseupdate: offline targets custody required")
	}
	lock, err := acquireLock(p.cfg.Directory)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	root, err := p.root()
	if err != nil {
		return err
	}
	current, err := p.current(root)
	if err != nil {
		return err
	}
	info, err := p.importTarget(ctx, name, source)
	if err != nil {
		return err
	}
	if strings.HasPrefix(name, "recovery/") {
		expected, err := RecoveryTargetPath(info.Hashes["sha256"])
		if err != nil || name != expected {
			return errors.New("releaseupdate: recovery target name does not match image digest")
		}
	}
	if previous := current.targets.Signed.Targets[name]; previous != nil {
		if previous.Length != info.Length || !bytes.Equal(previous.Hashes["sha256"], info.Hashes["sha256"]) {
			return errors.New("releaseupdate: artifact target already names different bytes")
		}
		// Preserve existing typed agent descriptors when re-publishing exact bytes.
		info.Custom = previous.Custom
	}
	current.targets.Signed.Targets[name] = info
	return p.commit(ctx, root, current, true)
}
