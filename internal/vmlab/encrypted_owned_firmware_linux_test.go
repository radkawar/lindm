package vmlab

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func ownedFirmwareCertificateFixture(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "disposable firmware signer"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestOwnedFirmwareCertificatePublicOnly(t *testing.T) {
	der, public := ownedFirmwareCertificateFixture(t)
	private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not public material")})
	for _, test := range []struct {
		name      string
		data      []byte
		wantError bool
	}{
		{"single public", public, false},
		{"whitespace", append([]byte(" \n"), public...), false},
		{"DER instead of PEM", der, true},
		{"private key", private, true},
		{"appended key", bytes.Join([][]byte{public, private}, nil), true},
		{"prepended key", bytes.Join([][]byte{private, public}, nil), true},
		{"certificate bundle", bytes.Join([][]byte{public, public}, nil), true},
		{"leading garbage", append([]byte("ignored text\n"), public...), true},
		{"malformed leading certificate", append([]byte("-----BEGIN CERTIFICATE-----\ninvalid\n"), public...), true},
		{"trailing garbage", append(bytes.Clone(public), []byte("not certificate data")...), true},
		{"invalid DER", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid")}), true},
		{"headers", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der, Headers: map[string]string{"Comment": "unexpected"}}), true},
		{"oversized", bytes.Repeat([]byte(" "), (64<<10)+1), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			certificate, err := parseOwnedFirmwareCertificate(test.data)
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, want error %v", err, test.wantError)
			}
			if err == nil && !bytes.Equal(certificate.Raw, der) {
				t.Fatal("certificate DER identity changed")
			}
		})
	}
}

func TestOwnedFirmwareCertificateRejectsSymlink(t *testing.T) {
	_, public := ownedFirmwareCertificateFixture(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "certificate.pem")
	if err := os.WriteFile(path, public, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readOwnedFirmwareCertificate(path); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.pem")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readOwnedFirmwareCertificate(link); err == nil {
		t.Fatal("accepted linked certificate input")
	}
}

func ownedFirmwareSignatureFixture(certificate []byte) []byte {
	data := make([]byte, 28+16+len(certificate))
	copy(data, firmwareX509GUID)
	binary.LittleEndian.PutUint32(data[16:20], uint32(len(data)))
	binary.LittleEndian.PutUint32(data[24:28], uint32(16+len(certificate)))
	copy(data[44:], certificate)
	return data
}

func TestOwnedFirmwareDBRequiresExactDERAndValidLists(t *testing.T) {
	der, _ := ownedFirmwareCertificateFixture(t)
	valid := ownedFirmwareSignatureFixture(der)
	for _, test := range []struct {
		name      string
		mutate    func([]byte) []byte
		wantError bool
	}{
		{"exact DER", func(data []byte) []byte { return data }, false},
		{"wrong signature type", func(data []byte) []byte { data[0] ^= 1; return data }, true},
		{"different certificate", func(data []byte) []byte { data[len(data)-1] ^= 1; return data }, true},
		{"certificate prefix", func(data []byte) []byte { return ownedFirmwareSignatureFixture(der[:len(der)-1]) }, true},
		{"truncated header", func(data []byte) []byte { return data[:27] }, true},
		{"truncated signature", func(data []byte) []byte { return data[:len(data)-1] }, true},
		{"overflow list size", func(data []byte) []byte { binary.LittleEndian.PutUint32(data[16:20], ^uint32(0)); return data }, true},
		{"undersized list", func(data []byte) []byte { binary.LittleEndian.PutUint32(data[16:20], 27); return data }, true},
		{"overflow header", func(data []byte) []byte { binary.LittleEndian.PutUint32(data[20:24], ^uint32(0)); return data }, true},
		{"zero signature", func(data []byte) []byte { binary.LittleEndian.PutUint32(data[24:28], 0); return data }, true},
		{"owner only", func(data []byte) []byte { binary.LittleEndian.PutUint32(data[24:28], 16); return data }, true},
		{"invalid trailing list", func(data []byte) []byte { return append(data, 0) }, true},
		{"preceding other signer", func(data []byte) []byte {
			return append(ownedFirmwareSignatureFixture([]byte("other signer")), data...)
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ownedFirmwareDBContains(test.mutate(bytes.Clone(valid)), der)
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, want error %v", err, test.wantError)
			}
		})
	}
}

func TestOwnedFirmwareEnrollmentPreservesVendorTrust(t *testing.T) {
	der, _ := ownedFirmwareCertificateFixture(t)
	originalDB := ownedFirmwareSignatureFixture([]byte("original vendor signer"))
	fixture := func() []ownedFirmwareVariable {
		return []ownedFirmwareVariable{
			{Name: "PK", GUID: firmwareGlobalGUID, Attr: 39, Data: hex.EncodeToString(ownedFirmwareSignatureFixture([]byte("platform key")))},
			{Name: "KEK", GUID: firmwareGlobalGUID, Attr: 39, Data: hex.EncodeToString(ownedFirmwareSignatureFixture([]byte("exchange key")))},
			{Name: "db", GUID: firmwareDBGUID, Attr: 39, Data: hex.EncodeToString(originalDB)},
			{Name: "dbx", GUID: firmwareDBGUID, Attr: 39, Data: hex.EncodeToString(ownedFirmwareSignatureFixture([]byte("revoked signer")))},
			{Name: "SecureBootEnable", GUID: firmwareGlobalGUID, Attr: 3, Data: "01"},
		}
	}
	marshal := func(variables []ownedFirmwareVariable) []byte {
		t.Helper()
		data, err := json.Marshal(map[string]any{"version": 2, "variables": variables})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	before := marshal(fixture())
	for _, test := range []struct {
		name      string
		mutate    func([]ownedFirmwareVariable) []ownedFirmwareVariable
		wantError bool
	}{
		{"append signer only", func(v []ownedFirmwareVariable) []ownedFirmwareVariable { return v }, false},
		{"db timestamp update", func(v []ownedFirmwareVariable) []ownedFirmwareVariable {
			v[2].Time = "new-authenticated-timestamp"
			return v
		}, false},
		{"replace vendor db", func(v []ownedFirmwareVariable) []ownedFirmwareVariable {
			v[2].Data = hex.EncodeToString(ownedFirmwareSignatureFixture(der))
			return v
		}, true},
		{"drop PK", func(v []ownedFirmwareVariable) []ownedFirmwareVariable { return v[1:] }, true},
		{"change KEK", func(v []ownedFirmwareVariable) []ownedFirmwareVariable { v[1].Data += "00"; return v }, true},
		{"drop revocation", func(v []ownedFirmwareVariable) []ownedFirmwareVariable { v[3].Data = ""; return v }, true},
		{"change attributes", func(v []ownedFirmwareVariable) []ownedFirmwareVariable { v[2].Attr = 0; return v }, true},
		{"disable secure boot", func(v []ownedFirmwareVariable) []ownedFirmwareVariable { v[4].Data = "00"; return v }, true},
		{"missing signer", func(v []ownedFirmwareVariable) []ownedFirmwareVariable {
			v[2].Data = hex.EncodeToString(originalDB)
			return v
		}, true},
		{"MOK namespace", func(v []ownedFirmwareVariable) []ownedFirmwareVariable { v[2].GUID = firmwareGlobalGUID; return v }, true},
		{"duplicate db", func(v []ownedFirmwareVariable) []ownedFirmwareVariable { return append(v, v[2]) }, true},
		{"duplicate unrelated variable", func(v []ownedFirmwareVariable) []ownedFirmwareVariable { return append(v, v[4]) }, true},
		{"invalid data", func(v []ownedFirmwareVariable) []ownedFirmwareVariable { v[3].Data = "zz"; return v }, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			after := fixture()
			after[2].Data = hex.EncodeToString(bytes.Join([][]byte{originalDB, ownedFirmwareSignatureFixture(der)}, nil))
			err := validateOwnedFirmwareEnrollment(before, marshal(test.mutate(after)), der)
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, want error %v", err, test.wantError)
			}
		})
	}
}

func TestOwnedFirmwareRequiresSecureBoot(t *testing.T) {
	if _, err := prepareEncryptedFirmware(t.Context(), t.TempDir(), EncryptedFirmwareOptions{OwnedDBCertificate: "signer.pem"}); err == nil || err.Error() != "owned firmware db enrollment requires Secure Boot" {
		t.Fatalf("expected Secure Boot requirement before firmware access, got %v", err)
	}
}
