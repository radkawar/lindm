//go:build linux

package config

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// resolvePackageProvider uses the same custody boundary as executor configuration.
// The provider must recheck the exact key digest when staging an isolated native
// repository; this startup observation never authorizes a later replacement key.
func resolvePackageProvider(base string, cfg *agentv1.NativePackageProviderConfig, rootOwner bool) error {
	for _, source := range cfg.GetSources() {
		path := resolve(base, source.GetSigningKeyFile())
		key, err := readConfig(path, rootOwner)
		if err != nil {
			return fmt.Errorf("read approved package signing key: %w", err)
		}
		digest := sha256.Sum256(key)
		if !bytes.Equal(digest[:], source.GetSigningKeySha256()) {
			return fmt.Errorf("approved package signing key digest mismatch for repository %s", source.GetRepository().GetRepositoryId())
		}
		source.SigningKeyFile = path
	}
	return nil
}
