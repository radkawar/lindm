// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"lindm/internal/rpcreason"
)

func TestUnattendedSeedConfinesCredentialsToRootFiles(t *testing.T) {
	const secret = "sensitive-provisioning-token"
	seed := &unattendedSeed{root: []byte("verified-root"), bundle: []byte("signed-bootstrap"), token: []byte(secret)}
	config := map[string]any{"runcmd": []any{[]string{"true"}}}
	seed.apply(config)
	files, ok := config["write_files"].([]any)
	if !ok {
		t.Fatal("seed did not add write_files")
	}
	if len(files) != 3 {
		t.Fatal("missing protected bootstrap documents")
	}
	seenToken := false
	for _, value := range files {
		file, ok := value.(map[string]any)
		if !ok {
			t.Fatal("write_files entry is not a mapping")
		}
		if file["owner"] != "root:root" || file["permissions"] != "0600" || file["encoding"] != "b64" {
			t.Fatal("boot material lost root-only file boundary")
		}
		path, ok := file["path"].(string)
		if !ok || !strings.HasPrefix(path, unattendedDirectory+"/") {
			t.Fatal("material escaped owned runtime directory")
		}
		encoded, ok := file["content"].(string)
		if !ok {
			t.Fatal("write_files content is not a string")
		}
		content, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if file["path"] == unattendedDirectory+"/token" {
			seenToken = string(content) == secret
		}
	}
	if !seenToken {
		t.Fatal("boot credential bytes changed")
	}
	commands, ok := config["runcmd"].([]any)
	if !ok {
		t.Fatal("runcmd is not a list")
	}
	for _, command := range commands {
		arguments, ok := command.([]string)
		if !ok {
			t.Fatal("runcmd entry is not an argument vector")
		}
		for _, argument := range arguments {
			if strings.Contains(argument, secret) || strings.Contains(argument, base64.StdEncoding.EncodeToString([]byte(secret))) {
				t.Fatal("credential leaked into boot command arguments")
			}
		}
	}
}

func TestUnattendedExhaustionRequiresExactServerDenial(t *testing.T) {
	for _, test := range []struct {
		code     connect.Code
		reason   string
		accepted bool
	}{
		{connect.CodeResourceExhausted, "provisioning_token_exhausted", true},
		{connect.CodeResourceExhausted, "", false},
		{connect.CodePermissionDenied, "provisioning_token_revoked", false},
		{connect.CodePermissionDenied, "provisioning_token_expired", false},
		{connect.CodeUnavailable, "provisioning_token_exhausted", false},
		{connect.CodeInvalidArgument, "provisioning_token_exhausted", false},
	} {
		rpc := connect.NewError(test.code, errors.New("private response must never be recorded"))
		rpcreason.Set(rpc, test.reason)
		reason, err := unattendedExhaustionReason(rpc)
		if (err == nil) != test.accepted {
			t.Fatalf("code %s reason %q accepted=%v", test.code, test.reason, err == nil)
		}
		if err != nil && strings.Contains(err.Error(), "private response") {
			t.Fatal("remote error content leaked")
		}
		if test.accepted && reason != test.reason {
			t.Fatal("evidence lost exact observed reason")
		}
	}
	for _, err := range []error{nil, errors.New("sensitive local failure")} {
		if _, observed := unattendedExhaustionReason(err); observed == nil {
			t.Fatal("non-RPC outcome became exhaustion evidence")
		}
	}
}
