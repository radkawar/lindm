package ctl

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	authv1 "lindm/gen/lindm/auth/v1"
)

func testClient(t *testing.T, handler http.Handler) (*Client, string, *authv1.CLIConfig) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	config := &authv1.CLIConfig{ServerOrigin: server.URL, CaPem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "lindm", "config.json")
	client, err := New(path, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	return client, path, config
}

func writeProto(t *testing.T, w http.ResponseWriter, message proto.Message) {
	t.Helper()
	data, err := protojson.Marshal(message)
	if err != nil {
		t.Error(err)
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(data); err != nil {
		t.Error(err)
	}
}

func getCallback(t *testing.T, target string, expected int) {
	t.Helper()
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != expected {
		t.Fatalf("callback status = %d, want %d", response.StatusCode, expected)
	}
}

func testToken(t *testing.T) string {
	t.Helper()
	token, err := randomToken()
	if err != nil {
		t.Fatal(err)
	}
	return token
}
