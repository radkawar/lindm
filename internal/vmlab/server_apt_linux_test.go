// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAPTPublicServerServesBothProductsWithoutSecrets(t *testing.T) {
	root := t.TempDir()
	names := []string{"pool/main/l/lindmd/lindmd_0.1.0_amd64.deb", "pool/main/l/lindm-agent/lindm-agent_0.1.0_amd64.deb"}
	for _, name := range names {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "server.key"), []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	server, err := newAPTPublicServer(root, names)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	}()
	client := &http.Client{Timeout: 5 * time.Second}
	for _, name := range append(names, "server.key", "pool/main/l/lindmd/") {
		response, err := client.Get("http://" + server.listener.Addr().String() + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 4096))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil {
			t.Fatalf("read response: %v %v", readErr, closeErr)
		}
		if name == names[0] || name == names[1] {
			if response.StatusCode != http.StatusOK || string(data) != name {
				t.Fatalf("public package %s not served", name)
			}
		} else if response.StatusCode != http.StatusNotFound {
			t.Fatalf("unlisted path %s disclosed", name)
		}
	}
	if rejected, err := newAPTPublicServer(root, []string{"server.key"}); err == nil {
		_ = rejected.Close()
		t.Fatal("private file admitted to public allowlist")
	}
}
