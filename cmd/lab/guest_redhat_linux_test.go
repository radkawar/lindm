//go:build linux

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	labv1 "lindm/gen/lindm/lab/v1"
)

func TestRedHatGuestInputSuppressesRejectedCredentials(t *testing.T) {
	const secret = "rejected-sensitive-material"
	for _, payload := range []string{
		`{"organization_id":"` + secret + `","activation_key":"lindm-lab-0123456789abcdef0123456789abcdef","run_name":"lindm-lab-fedcba9876543210fedcba9876543210"}`,
		`{"organization_id":"123","activation_key":"` + secret + `","run_name":"lindm-lab-fedcba9876543210fedcba9876543210"}`,
		`{"organization_id":"123","activation_key":"lindm-lab-0123456789abcdef0123456789abcdef","run_name":"lindm-lab-fedcba9876543210fedcba9876543210","unknown":"` + secret + `"}`,
		`{"organization_id":"` + secret,
		strings.Repeat(secret, 256),
		"",
	} {
		result, err := decodeRedHatGuestInput([]byte(payload))
		if err == nil || len(result) != 0 {
			t.Fatal("invalid registration material accepted")
		}
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "0123456789abcdef") {
			t.Fatal("registration diagnostic exposed input")
		}
	}
}

func TestRedHatGuestInputUsesExistingProtobufContract(t *testing.T) {
	const key = "lindm-lab-0123456789abcdef0123456789abcdef"
	const runName = "lindm-lab-fedcba9876543210fedcba9876543210"
	payload, err := decodeRedHatGuestInput([]byte(`{"organizationId":"123","activationKey":"` + key + `","runName":"` + runName + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(payload)
	credentials := new(labv1.RedHatRegistrationCredentials)
	if err := protojson.Unmarshal(payload, credentials); err != nil {
		t.Fatal("normalized credentials are not protobuf JSON")
	}
	if credentials.GetOrganizationId() != "123" || credentials.GetActivationKey() != key || credentials.GetRunName() != runName {
		t.Fatal("registration input lost contract fields")
	}
	if !strings.Contains(string(payload), `"organization_id"`) || !strings.Contains(string(payload), `"activation_key"`) || !strings.Contains(string(payload), `"run_name"`) {
		t.Fatal("native guest delivery must use canonical protobuf field names")
	}
}

func TestRedHatEnabledRepositoriesRequireNativeRows(t *testing.T) {
	for _, test := range []struct {
		output string
		want   bool
	}{
		{output: ""},
		{output: "Updating Subscription Management repositories.\nNo repositories available\n"},
		{output: "repo id                 repo name\n"},
		{output: "Updating Subscription Management repositories.\nrepo id                 repo name\nrhel-9-for-x86_64-baseos-rpms  Red Hat Enterprise Linux 9 BaseOS\n", want: true},
	} {
		if got := redHatEnabledRepositories([]byte(test.output)); got != test.want {
			t.Fatalf("enabled repository observation = %t, want %t", got, test.want)
		}
	}
}

func TestRedHatGuestRejectsUnsafePublicNames(t *testing.T) {
	const key = "lindm-lab-0123456789abcdef0123456789abcdef"
	for _, name := range []string{"", key, "vendor-host", "lindm-lab-ABCDEF0123456789abcdef0123456789", "lindm-lab-123", "sensitive-material"} {
		payload := `{"organization_id":"123","activation_key":"` + key + `","run_name":"` + name + `"}`
		if output, err := decodeRedHatGuestInput([]byte(payload)); err == nil || len(output) != 0 {
			t.Fatal("unsafe or credential-derived public name accepted")
		} else if strings.Contains(err.Error(), key) || strings.Contains(err.Error(), "sensitive-material") {
			t.Fatal("name validation leaked input")
		}
	}
	if !strings.Contains(redHatSubscriptionScript, `"--name", material["run_name"]`) {
		t.Fatal("native registration must receive the independent public name in memory")
	}
}

func TestRedHatConsumerCertificateIdentity(t *testing.T) {
	const runName = "lindm-lab-fedcba9876543210fedcba9876543210"
	const consumer = "01234567-89ab-cdef-0123-456789abcdef"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, cn := range []string{consumer, "", "sensitive-account-material", "00000000-0000-0000-0000-000000000000", "0123456789abcdef0123456789abcdef", "01234567-89AB-CDEF-0123-456789ABCDEF"} {
		certificate := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: cn, Organization: []string{"sensitive-account-material"}},
			NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		identity, err := redHatCertificateIdentity(data, runName)
		if cn != consumer {
			if err == nil || identity != nil || strings.Contains(err.Error(), "sensitive-account-material") {
				t.Fatal("malformed native identity accepted or disclosed")
			}
			continue
		}
		if err != nil || identity.GetConsumerUuid() != consumer || identity.GetRunName() != runName {
			t.Fatal("native certificate consumer UUID was not retained")
		}
		output, err := protojson.Marshal(identity)
		if err != nil || strings.Contains(string(output), "sensitive-account-material") {
			t.Fatal("public identity output exposed certificate account data")
		}
		for _, malformed := range [][]byte{append(data, []byte("extra-sensitive-material")...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), []byte("sensitive-account-material")} {
			if identity, err := redHatCertificateIdentity(malformed, runName); err == nil || identity != nil || strings.Contains(err.Error(), "sensitive") {
				t.Fatal("malformed certificate accepted or disclosed")
			}
		}
	}
}
