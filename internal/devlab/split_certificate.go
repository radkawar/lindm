package devlab

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

func validateSplitDevice(device netip.Addr) error {
	if !device.Is4() || !device.IsGlobalUnicast() || device.IsLoopback() {
		return errors.New("split authority device listener requires a specific non-loopback unicast IPv4 address")
	}
	return nil
}

// writeSplitCertificate reads shared CA custody but writes only fresh run-owned
// files. Shared server certificates and their validation are deliberately untouched.
func writeSplitCertificate(shared, directory string, device netip.Addr) error {
	if err := validateSplitDevice(device); err != nil {
		return err
	}
	ca, err := tls.LoadX509KeyPair(filepath.Join(shared, "transport-ca.crt"), filepath.Join(shared, "transport-ca.key"))
	if err != nil {
		return fmt.Errorf("load split transport CA: %w", err)
	}
	parent, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse split transport CA: %w", err)
	}
	now := time.Now()
	if !parent.IsCA || now.Before(parent.NotBefore) || !now.Before(parent.NotAfter) {
		return errors.New("split transport CA is not a currently valid CA")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate split TLS key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate split TLS serial: %w", err)
	}
	expires := now.Add(24 * time.Hour)
	if parent.NotAfter.Before(expires) {
		expires = parent.NotAfter
	}
	leaf := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "lindm split laboratory"},
		NotBefore: now.Add(-time.Minute), NotAfter: expires,
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IP(device.AsSlice()), net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, parent, &key.PublicKey, ca.PrivateKey)
	if err != nil {
		return fmt.Errorf("sign split TLS certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("encode split TLS key: %w", err)
	}
	defer clear(keyDER)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	defer clear(keyPEM)
	if err := writeSplitPrivateFile(filepath.Join(directory, "split-server.key"), keyPEM); err != nil {
		return err
	}
	return writeSplitPrivateFile(filepath.Join(directory, "split-server.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func writeSplitPrivateFile(path string, data []byte) (resultErr error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create split TLS file: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write split TLS file: %w", err)
	}
	return nil
}
