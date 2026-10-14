// SPDX-License-Identifier: Apache-2.0

package privatecustody

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func custodyDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestCustodyRoundTripNonceEqualityAndBinding(t *testing.T) {
	directory, installation := custodyDirectory(t), uuid.NewString()
	custody, err := Initialize(directory, installation)
	if err != nil {
		t.Fatal(err)
	}
	defer custody.Close()
	secret := []byte("$6$private-baseline-hash")
	binding := Binding("native-result", "action-one", "revision-1")
	first, err := custody.Seal(secret, binding)
	if err != nil {
		t.Fatal(err)
	}
	second, err := custody.Seal(secret, binding)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.GetNonce(), second.GetNonce()) || bytes.Equal(first.GetCiphertext(), second.GetCiphertext()) || !bytes.Equal(first.GetEqualityTag(), second.GetEqualityTag()) {
		t.Fatal("fresh encryption nonce or keyed equality contract violated")
	}
	encoded, err := proto.Marshal(first)
	if err != nil || bytes.Contains(encoded, secret) {
		t.Fatal("private plaintext escaped encryption")
	}
	for _, mutate := range []func(*agentv1.PrivateCustodyEnvelope){
		func(e *agentv1.PrivateCustodyEnvelope) { e.Ciphertext[0]++ },
		func(e *agentv1.PrivateCustodyEnvelope) { e.Nonce[0]++ },
		func(e *agentv1.PrivateCustodyEnvelope) { e.KeyId[0]++ },
		func(e *agentv1.PrivateCustodyEnvelope) { e.EqualityTag[0]++ },
		func(e *agentv1.PrivateCustodyEnvelope) { e.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01}) },
	} {
		changed := proto.CloneOf(first)
		mutate(changed)
		if plaintext, err := custody.Open(changed, binding); err == nil || plaintext != nil {
			t.Fatal("corrupt envelope returned private plaintext")
		}
	}
	if plaintext, err := custody.Open(first, Binding("native-request", "action-one", "revision-1")); err == nil || plaintext != nil {
		t.Fatal("ciphertext transferred between consumer types")
	}
	if plaintext, err := custody.Open(first, Binding("native-result", "action-one", "revision-2")); err == nil || plaintext != nil {
		t.Fatal("ciphertext replayed across revisions")
	}
	custody.Close()
	reopened, err := Open(directory, installation)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	plaintext, err := reopened.Open(first, binding)
	if err != nil || !bytes.Equal(plaintext, secret) {
		t.Fatal("durable key could not restore exact baseline")
	}
	clear(plaintext)
	if _, err := Open(directory, uuid.NewString()); err == nil {
		t.Fatal("key accepted foreign installation")
	}
	if _, err := Initialize(directory, installation); err == nil {
		t.Fatal("existing installation key replaced")
	}
}

func TestCustodyMissingCorruptAndUnsafeKeysNeverRegenerate(t *testing.T) {
	for _, damage := range []string{"missing", "truncated", "mode", "symlink", "hardlink"} {
		t.Run(damage, func(t *testing.T) {
			directory, installation := custodyDirectory(t), uuid.NewString()
			custody, err := Initialize(directory, installation)
			if err != nil {
				t.Fatal(err)
			}
			custody.Close()
			path := filepath.Join(directory, KeyFileName)
			switch damage {
			case "missing":
				err = os.Remove(path)
			case "truncated":
				err = os.Truncate(path, 32)
			case "mode":
				err = os.Chmod(path, 0644)
			case "symlink":
				err = os.Rename(path, path+".target")
				if err == nil {
					err = os.Symlink(path+".target", path)
				}
			case "hardlink":
				err = os.Link(path, path+".linked")
			}
			if err != nil {
				t.Fatal(err)
			}
			if reopened, err := Open(directory, installation); err == nil {
				reopened.Close()
				t.Fatal("damaged custody key accepted")
			}
			if damage == "missing" {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("opening recreated missing custody key")
				}
			}
		})
	}
}

func TestOpenLocalAndPrivateDigestShareInstallationKey(t *testing.T) {
	directory, installation := custodyDirectory(t), uuid.NewString()
	custody, err := Initialize(directory, installation)
	if err != nil {
		t.Fatal(err)
	}
	defer custody.Close()
	if _, err := OpenLocal(directory); err == nil {
		t.Fatal("native helper opened key without immutable installation marker")
	}
	if err := os.WriteFile(filepath.Join(directory, "installation"), []byte(installation+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	helper, err := OpenLocal(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer helper.Close()
	contents := []byte("alice:$6$private-shadow-value")
	first, err := custody.Digest("accountprovider.database-file.v1:/etc/shadow", contents)
	if err != nil {
		t.Fatal(err)
	}
	second, err := helper.Digest("accountprovider.database-file.v1:/etc/shadow", contents)
	if err != nil || !bytes.Equal(first, second) || len(first) != 32 {
		t.Fatal("native helper and journal keyed revisions differ")
	}
	other, err := helper.Digest("accountprovider.identity.v1:shadow:alice", contents)
	if err != nil || bytes.Equal(first, other) {
		t.Fatal("private digest domains collapsed")
	}
	helper.Close()
	if _, err := helper.Digest("closed", contents); err == nil {
		t.Fatal("closed custody continued using erased key")
	}
}
