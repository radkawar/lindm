// SPDX-License-Identifier: Apache-2.0

//go:build linux

package labhost

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestEnrollmentBrowserStagingPreservesCredentialCustody(t *testing.T) {
	root := t.TempDir()
	credential := filepath.Join(root, "credential.json")
	if err := os.WriteFile(credential, []byte("private passkey material"), 0600); err != nil {
		t.Fatal(err)
	}
	evidence := filepath.Join(root, "screenshots")
	configPath := filepath.Join(root, "capture.json")
	config := map[string]any{"credentialPath": credential, "evidenceDirectory": evidence, "origin": "https://localhost:37429", "password": "private-password", "enrollmentSecret": "expired-bootstrap", "resultPath": "/controller/private-result.json", "enrollmentCommandPaths": map[string]string{"apt": "/controller/grant.sh"}}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	stage := &remoteStage{ctx: t.Context(), local: t.TempDir(), remote: t.TempDir(), stderr: io.Discard, copied: make(map[string]string)}
	outputs := make(map[string]string)
	staged, err := stage.enrollmentBrowser(configPath, outputs)
	if err != nil {
		t.Fatal(err)
	}
	data, err = readEnrollmentBrowserFile(staged)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	var stagedCredential, stagedEvidence, password string
	for field, target := range map[string]*string{"credentialPath": &stagedCredential, "evidenceDirectory": &stagedEvidence, "password": &password} {
		if err := json.Unmarshal(got[field], target); err != nil {
			t.Fatal(err)
		}
	}
	if stagedCredential != filepath.Join(stage.remote, "records", "browser-credential") || stagedEvidence != filepath.Join(stage.remote, "records", "evidence") || outputs["evidence"] != evidence || outputs["browser-credential"] != credential || password != "private-password" {
		t.Fatal("capture paths or credential payload changed incorrectly")
	}
	for _, field := range []string{"resultPath", "enrollmentCommandPaths", "enrollmentSecret"} {
		if _, present := got[field]; present {
			t.Fatalf("controller-only %s retained", field)
		}
	}
	content, err := os.ReadFile(stagedCredential)
	if err != nil || string(content) != "private passkey material" {
		t.Fatal("staged passkey material changed")
	}
	info, err := os.Stat(stagedCredential)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("staged passkey permissions weakened")
	}
	if err := os.WriteFile(stagedCredential, []byte("updated authenticator counter"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := returnEnrollmentCredential(stagedCredential, credential); err != nil {
		t.Fatal(err)
	}
	content, err = readEnrollmentBrowserFile(credential)
	if err != nil || string(content) != "updated authenticator counter" {
		t.Fatal("updated authenticator state was not returned privately")
	}
	linked := filepath.Join(root, "linked-credential")
	if err := os.Symlink(credential, linked); err != nil {
		t.Fatal(err)
	}
	if err := returnEnrollmentCredential(stagedCredential, linked); err == nil {
		t.Fatal("credential return followed a symlink")
	}
	if err := os.Chmod(configPath, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := stage.enrollmentBrowser(configPath, outputs); err == nil {
		t.Fatal("non-private owner config accepted")
	}
}

func TestProvisioningBrowserStagingRelocatesApproverCredential(t *testing.T) {
	root := t.TempDir()
	owner, approver := filepath.Join(root, "owner.json"), filepath.Join(root, "approver.json")
	for path, content := range map[string]string{owner: "owner passkey", approver: "approver passkey"} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(root, "provision.json")
	write := func(config map[string]any) {
		t.Helper()
		data, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(configPath, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	const rules = "MAP lindm-console.test 127.0.0.1"
	write(map[string]any{"credentialPath": owner, "evidenceDirectory": filepath.Join(root, "screenshots"), "origin": "https://lindm-console.test:37429", "password": "owner-password", "hostResolverRules": rules, "provisionSnippetPath": "/controller/snippet",
		"approver": map[string]string{"username": "console-approver", "password": "approver-password", "credentialPath": approver}})
	stage := &remoteStage{ctx: t.Context(), local: t.TempDir(), remote: t.TempDir(), stderr: io.Discard, copied: make(map[string]string)}
	outputs := make(map[string]string)
	staged, err := stage.enrollmentBrowser(configPath, outputs)
	if err != nil {
		t.Fatal(err)
	}
	data, err := readEnrollmentBrowserFile(staged)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		HostResolverRules string            `json:"hostResolverRules"`
		SnippetPath       *string           `json:"provisionSnippetPath"`
		Approver          map[string]string `json:"approver"`
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	stagedApprover := filepath.Join(stage.remote, "records", "approver-credential")
	if got.HostResolverRules != rules || got.SnippetPath != nil || got.Approver["credentialPath"] != stagedApprover || got.Approver["username"] != "console-approver" || got.Approver["password"] != "approver-password" {
		t.Fatal("approver, resolver or controller-only fields staged incorrectly")
	}
	if outputs["approver-credential"] != approver || outputs["browser-credential"] != owner {
		t.Fatal("approver credential is not returned to its own private file")
	}
	content, err := os.ReadFile(stagedApprover)
	if err != nil || string(content) != "approver passkey" {
		t.Fatal("staged approver passkey changed")
	}
	write(map[string]any{"credentialPath": owner, "evidenceDirectory": filepath.Join(root, "other-screenshots"), "approver": map[string]string{"credentialPath": owner}})
	if _, err := stage.enrollmentBrowser(configPath, make(map[string]string)); err == nil {
		t.Fatal("approver sharing the owner's credential file accepted")
	}
}
