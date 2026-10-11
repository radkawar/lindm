package recoveryboot

import (
	"crypto/ed25519"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestOneActionKeyRejectsOrdinaryCredentialAndMutation(t *testing.T) {
	oneAction := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	ordinarySeed := make([]byte, ed25519.SeedSize)
	ordinarySeed[0] = 1
	ordinary := ed25519.NewKeyFromSeed(ordinarySeed)
	public := oneAction[ed25519.SeedSize:]
	if err := credentialMatches(oneAction, public); err != nil {
		t.Fatal(err)
	}
	for _, key := range []ed25519.PrivateKey{ordinary, nil, oneAction[:31]} {
		if err := credentialMatches(key, public); err == nil {
			t.Fatal("ordinary/malformed credential accepted for one action")
		}
	}
	changed := append([]byte(nil), public...)
	changed[0] ^= 1
	if err := credentialMatches(oneAction, changed); err == nil {
		t.Fatal("mutated credential binding accepted")
	}
}

func TestCustodyRejectsUnownedLinkedOrMissingDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := ProvisionKey(filepath.Join(dir, "action.key")); err == nil {
		t.Fatal("key provisioned in writable custody")
	}
	if _, err := LoadKey(filepath.Join(dir, "missing.key")); err == nil {
		t.Fatal("missing key silently replaced")
	}
	link := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ProvisionKey(filepath.Join(link, "action.key")); err == nil {
		t.Fatal("key provisioned through symlink")
	}
	if _, err := os.Stat(filepath.Join(dir, "action.key")); !os.IsNotExist(err) {
		t.Fatal("rejected custody left a credential")
	}
}

func TestFirmwareDBRequiresExactSignerAndWellFormedList(t *testing.T) {
	cert := []byte("exact DER signer fixture")
	guid := []byte{0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a, 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72}
	size := 28 + 16 + len(cert)
	db := make([]byte, 4+size)
	copy(db[4:], guid)
	binary.LittleEndian.PutUint32(db[20:], uint32(size))
	binary.LittleEndian.PutUint32(db[28:], uint32(16+len(cert)))
	copy(db[4+28+16:], cert)
	if !certificateInDB(db, cert) {
		t.Fatal("enrolled exact signer not found")
	}
	if certificateInDB(db, []byte("different signer")) {
		t.Fatal("unapproved signer accepted")
	}
	for _, cut := range []int{0, 3, 4, 20, len(db) - 1} {
		if certificateInDB(db[:cut], cert) {
			t.Fatalf("truncated db accepted at %d", cut)
		}
	}
	binary.LittleEndian.PutUint32(db[28:], 0)
	if certificateInDB(db, cert) {
		t.Fatal("zero signature size accepted")
	}
}

// The strict ancestry walk rejects group-writable directories that the old
// TrustedDirectory boundary accepted when group-owned by gid 0.
func TestRootDirectoryRejectsGroupWritable(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 0, 0); err != nil && os.Geteuid() == 0 {
		t.Fatal(err)
	}
	if err := rootDirectory(dir); err == nil {
		t.Fatal("group-writable directory accepted")
	}
	if err := rootDirectory("/usr"); err != nil {
		t.Fatalf("root-owned directory rejected: %v", err)
	}
}
