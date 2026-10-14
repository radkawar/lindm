// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	configv1 "lindm/gen/lindm/config/v1"
)

func TestPersistentDirectoryCustodyAndLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authority")
	dir, lock, fresh, err := lockPersistentDirectory(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if !fresh || dir != path {
		t.Fatal("first open did not create exact state directory")
	}
	if _, second, _, err := lockPersistentDirectory(path, true); err == nil {
		_ = second.Close()
		t.Fatal("concurrent open acquired live fixture")
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	_, resumed, fresh, err := lockPersistentDirectory(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if fresh {
		t.Error("existing state was treated as new")
	}
	if err := resumed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
	if _, lock, _, err := lockPersistentDirectory(path, true); err == nil {
		_ = lock.Close()
		t.Fatal("public state directory admitted")
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, lock, _, err := lockPersistentDirectory(alias, true); err == nil {
		_ = lock.Close()
		t.Fatal("symlink state directory admitted")
	}
}

func TestPersistentCredentialCounterAndPermissions(t *testing.T) {
	account, err := newLocalAccount("localhost", "test-owner", uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	defer (&localAuthority{owner: account}).close()
	account.statePath, account.counter = filepath.Join(t.TempDir(), "owner.json"), 7
	if err := account.persist(); err != nil {
		t.Fatal(err)
	}
	restored, err := restorePersistentAccount(account.statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer (&localAuthority{owner: restored}).close()
	if restored.id != account.id || restored.counter != 7 || string(restored.password) != string(account.password) {
		t.Fatal("restored credential changed")
	}
	restored.counter++
	if err := restored.persist(); err != nil {
		t.Fatal(err)
	}
	updated, err := restorePersistentAccount(account.statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer (&localAuthority{owner: updated}).close()
	if updated.counter != 8 {
		t.Fatal("latest authentication counter did not survive reopen")
	}
	info, err := os.Stat(account.statePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("credential mode %o", info.Mode().Perm())
	}
	if err := os.Chmod(account.statePath, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := restorePersistentAccount(account.statePath); err == nil {
		t.Fatal("public credential admitted")
	}
}

func TestPersistentPortsRefuseTakenAddress(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatal("TCP listener did not return TCP address")
	}
	cfg := &configv1.ServerConfig{AdminListener: &configv1.ListenerConfig{Address: "127.0.0.1", Port: uint32(address.Port)}}
	if err := checkPersistentPorts(cfg); err == nil {
		t.Fatal("busy persisted port silently replaced")
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := checkPersistentPorts(cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.AdminListener.Port != uint32(address.Port) {
		t.Fatal("resume changed persisted port")
	}
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := packet.Close(); err != nil {
			t.Error(err)
		}
	}()
	packetAddress, ok := packet.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatal("UDP listener did not return UDP address")
	}
	cfg.Assistance = &configv1.AssistanceConfig{Relay: &configv1.AssistanceRelayConfig{Listener: &configv1.ListenerConfig{Address: "127.0.0.1", Port: uint32(packetAddress.Port)}}}
	if err := checkPersistentPorts(cfg); err == nil {
		t.Fatal("busy persisted TURN UDP port admitted")
	}
}

func TestDestroyPersistentAuthorityRequiresOwnedStoppedState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lane")
	_, lock, _, err := lockPersistentDirectory(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := writePersistentJSON(filepath.Join(path, "connected.json"), 1); err != nil {
		t.Fatal(err)
	}
	if err := DestroyPersistentAuthorityFixture(path); err == nil {
		t.Fatal("destroy admitted live lane")
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := DestroyPersistentAuthorityFixture(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destroy retained state: %v", err)
	}
	unrelated := t.TempDir()
	if err := DestroyPersistentAuthorityFixture(unrelated); err == nil {
		t.Fatal("destroy accepted unrelated directory")
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatal("destroy removed unrelated directory")
	}
}

func TestPersistentConfigPublicationKeepsOldReaderIntact(t *testing.T) {
	fixture := &AuthorityFixture{directory: t.TempDir(), persistent: true}
	if err := fixture.writeConfig([]byte(`{"version":1}`)); err != nil {
		t.Fatal(err)
	}
	old, err := os.Open(fixture.configPath())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := old.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := fixture.writeConfig([]byte(`{"version":2,"complete":true}`)); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 128)
	n, err := old.Read(data)
	if err != nil || string(data[:n]) != `{"version":1}` {
		t.Fatalf("config publication truncated or changed an existing reader: %q, %v", data[:n], err)
	}
	updated, err := os.ReadFile(fixture.configPath())
	if err != nil || string(updated) != `{"version":2,"complete":true}` {
		t.Fatalf("config publication did not publish the complete replacement: %q, %v", updated, err)
	}
	info, err := os.Stat(fixture.configPath())
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("published config is not private: %v", err)
	}
	entries, err := os.ReadDir(fixture.directory)
	if err != nil || len(entries) != 1 {
		t.Fatalf("publication retained temporary state: %v, %v", entries, err)
	}
}
