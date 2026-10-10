package deploylab

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"
)

// CertificateFiles creates short-lived, isolated laboratory certificates using
// the same standard-library PKI pattern as devlab. It is not a production CA.
// The transport signing key stays in memory; only the server's device CA key
// is returned. Neither these fixtures nor their trust roots are shared with dev.
func CertificateFiles() (map[string][]byte, error) {
	files := make(map[string][]byte)
	var transport *x509.Certificate
	var transportKey *ecdsa.PrivateKey
	now := time.Now()
	for _, name := range []string{"transport-ca", "device-ca", "server", "postgres"} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return nil, err
		}
		cert := &x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: "lindm isolated deployment proof " + name},
			NotBefore:    now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
			BasicConstraintsValid: true,
		}
		parent, signer := cert, key
		if name == "server" || name == "postgres" {
			cert.DNSNames = []string{"localhost"}
			if name == "postgres" {
				cert.DNSNames = append(cert.DNSNames, "postgres")
			}
			cert.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
			cert.KeyUsage = x509.KeyUsageDigitalSignature
			cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			parent, signer = transport, transportKey
		} else {
			cert.IsCA = true
			cert.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		}
		der, err := x509.CreateCertificate(rand.Reader, cert, parent, &key.PublicKey, signer)
		if err != nil {
			return nil, err
		}
		files[name+".crt"] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		if name == "transport-ca" {
			transport, transportKey = cert, key
			continue
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		files[name+".key"] = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	}
	return files, nil
}
