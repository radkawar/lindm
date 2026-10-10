//go:build linux

package main

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	labv1 "lindm/gen/lindm/lab/v1"
)

func TestRedHatGuestInputSuppressesRejectedCredentials(t *testing.T) {
	const secret = "rejected-sensitive-material"
	for _, payload := range []string{
		`{"organization_id":"` + secret + `","activation_key":"lindm-lab-0123456789abcdef0123456789abcdef"}`,
		`{"organization_id":"123","activation_key":"` + secret + `"}`,
		`{"organization_id":"123","activation_key":"lindm-lab-0123456789abcdef0123456789abcdef","unknown":"` + secret + `"}`,
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
	payload, err := decodeRedHatGuestInput([]byte(`{"organizationId":"123","activationKey":"` + key + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(payload)
	credentials := new(labv1.RedHatRegistrationCredentials)
	if err := protojson.Unmarshal(payload, credentials); err != nil {
		t.Fatal("normalized credentials are not protobuf JSON")
	}
	if credentials.GetOrganizationId() != "123" || credentials.GetActivationKey() != key {
		t.Fatal("registration input lost contract fields")
	}
	if !strings.Contains(string(payload), `"organization_id"`) || !strings.Contains(string(payload), `"activation_key"`) {
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
