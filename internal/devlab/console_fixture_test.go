package devlab

import (
	"os"
	"path/filepath"
	"testing"

	configv1 "lindm/gen/lindm/config/v1"
)

func TestConsoleIntegrationsUseOwnedProtectedKey(t *testing.T) {
	fixture := &AuthorityFixture{directory: t.TempDir()}
	cfg := new(configv1.ServerConfig)
	if err := fixture.configureConsoleIntegrations(cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.GetIntegrations() == nil {
		t.Fatal("console integrations/report services were not configured")
	}
	keyFile := cfg.GetIntegrations().GetEncryptionKeyFile()
	if keyFile == "" || filepath.Base(keyFile) != keyFile {
		t.Fatal("integration key is not relative to the owned fixture")
	}
	path := filepath.Join(fixture.directory, keyFile)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != 32 {
		t.Fatal("integration encryption key is not a protected 32-byte file")
	}
}
