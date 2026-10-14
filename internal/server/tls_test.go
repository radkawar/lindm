// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net/http"
	"testing"
	"time"

	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/config"
)

func TestTLSListenersUseIndependentIdentitiesAndDeviceMTLS(t *testing.T) {
	device := listenerTestCertificate(t, false)
	console := listenerTestCertificate(t, true)
	for _, split := range []bool{false, true} {
		resources := &config.Resources{
			Proto: &configv1.ServerConfig{
				AdminListener:  &configv1.ListenerConfig{Address: "127.0.0.1", Port: 7444},
				DeviceListener: &configv1.ListenerConfig{Address: "127.0.0.1", Port: 7445},
			},
			ServerCertificate: device, DeviceCACertificate: device.Leaf,
		}
		wantDevice := console.Leaf
		resources.ServerCertificate = console
		if split {
			wantDevice = device.Leaf
			resources.ServerCertificate = device
			resources.Proto.AdminTls = &configv1.TLSConfig{CertificateFile: "admin.crt", PrivateKeyFile: "admin.key"}
			resources.AdminServerCertificate = console
			resources.AdminCACertificate = console.Leaf
		}
		admin, devices := tlsServers(t.Context(), resources, http.NewServeMux(), http.NewServeMux())
		if !admin.TLSConfig.Certificates[0].Leaf.Equal(console.Leaf) || !devices.TLSConfig.Certificates[0].Leaf.Equal(wantDevice) {
			t.Fatal("listener identity composition changed")
		}
		if admin.TLSConfig.MinVersion != tls.VersionTLS13 || admin.TLSConfig.ClientAuth != tls.NoClientCert || devices.TLSConfig.MinVersion != tls.VersionTLS13 || devices.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert {
			t.Fatal("listener TLS policy changed")
		}
		roots := x509.NewCertPool()
		roots.AddCert(device.Leaf)
		if !devices.TLSConfig.ClientCAs.Equal(roots) {
			t.Fatal("device mTLS client roots changed")
		}
	}
}

func listenerTestCertificate(t *testing.T, console bool) tls.Certificate {
	t.Helper()
	var key crypto.Signer
	if console {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key = private
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}
