//go:build linux

package vmlab

import (
	"bytes"
	"compress/gzip"
	"testing"
)

func TestRecoveryKernelConfigurationRegistryPaths(t *testing.T) {
	for template, want := range map[string]string{
		"/boot/config-%s":            "/boot/config-7.2.9-1-default",
		"/usr/lib/modules/%s/config": "/usr/lib/modules/7.2.9-1-default/config",
		"/proc/config.gz":            "/proc/config.gz",
	} {
		got, err := recoveryKernelConfigPath(template, "7.2.9-1-default")
		if err != nil || got != want {
			t.Fatalf("kernel config %q = %q, %v", template, got, err)
		}
	}
	for _, template := range []string{"", "relative/%s", "/boot/../config-%s", "/boot/%d", "/boot/%s\x00"} {
		if _, err := recoveryKernelConfigPath(template, "7.2.9-1-default"); err == nil {
			t.Fatalf("unsafe template accepted: %q", template)
		}
	}
	for _, release := range []string{"", ".", "..", "../foreign", "kernel/foreign", "kernel;reboot", "kernel\n"} {
		if _, err := recoveryKernelConfigPath("/boot/config-%s", release); err == nil {
			t.Fatalf("unsafe kernel release accepted: %q", release)
		}
	}
}

func TestRecoveryKernelConfigurationGZIPBoundaries(t *testing.T) {
	compress := func(payload []byte) []byte {
		t.Helper()
		var output bytes.Buffer
		writer := gzip.NewWriter(&output)
		if _, err := writer.Write(payload); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		return output.Bytes()
	}
	plain := []byte("CONFIG_RD_GZIP=y\nCONFIG_IKCONFIG_PROC=y\n")
	encoded := compress(plain)
	decoded, err := recoveryKernelConfigGZIP(encoded)
	if err != nil || !bytes.Equal(decoded, plain) {
		t.Fatalf("kernel configuration decode: %q, %v", decoded, err)
	}
	for name, input := range map[string][]byte{
		"not gzip":            plain,
		"truncated":           encoded[:len(encoded)-1],
		"oversized expansion": compress(bytes.Repeat([]byte{'x'}, (1<<20)+1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := recoveryKernelConfigGZIP(input); err == nil {
				t.Fatal("invalid kernel configuration accepted")
			}
		})
	}
}
