package devlab

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func certificateFiles() (map[string][]byte, error) {
	files := make(map[string][]byte)
	var transport *x509.Certificate
	var transportKey *ecdsa.PrivateKey
	for _, name := range []string{"transport-ca", "device-ca", "server"} {
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
			Subject:      pkix.Name{CommonName: "lindm local development " + name},
			NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(5, 0, 0),
			BasicConstraintsValid: true,
		}
		parent, signer := cert, key
		if name == "server" {
			cert.DNSNames = []string{"localhost"}
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
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		files[name+".crt"] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		files[name+".key"] = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		if name == "transport-ca" {
			transport, transportKey = cert, key
		}
	}
	return files, nil
}

func validateCertificates(dir string) error {
	var transport *x509.Certificate
	for _, name := range []string{"transport-ca", "device-ca", "server"} {
		pair, err := tls.LoadX509KeyPair(filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key"))
		if err != nil {
			return fmt.Errorf("%s key pair: %w", name, err)
		}
		cert, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return err
		}
		if time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) {
			return fmt.Errorf("%s certificate is not currently valid; stop the app, then run go run ./cmd/devenv reset -confirm-delete and up to regenerate (this destroys lab data)", name)
		}
		if name != "server" {
			if !cert.IsCA {
				return fmt.Errorf("%s is not a CA", name)
			}
			if err := cert.CheckSignatureFrom(cert); err != nil {
				return err
			}
		} else {
			roots := x509.NewCertPool()
			roots.AddCert(transport)
			if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: "localhost"}); err != nil {
				return err
			}
			for _, host := range []string{"127.0.0.1", "::1"} {
				if err := cert.VerifyHostname(host); err != nil {
					return err
				}
			}
		}
		if name == "transport-ca" {
			transport = cert
		}
	}
	return nil
}

func trustClient(dir string) (*tls.Config, error) {
	ca, err := os.ReadFile(filepath.Join(dir, "transport-ca.crt"))
	if err != nil {
		return nil, err
	}
	return trustClientPEM(ca)
}

func trustClientPEM(ca []byte) (*tls.Config, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("invalid development transport CA")
	}
	return &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}, nil
}
