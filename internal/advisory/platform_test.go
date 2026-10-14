// SPDX-License-Identifier: Apache-2.0

package advisory

import (
	"testing"

	"google.golang.org/protobuf/proto"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func TestRHELStreamRequiresCorroboratingNativeEvidence(t *testing.T) {
	for _, test := range []struct {
		name, release, cpe, lock, want string
		repositories                   []string
		repositoriesFailed             bool
	}{
		{"standard", "9.8", "cpe:/o:redhat:enterprise_linux:9::baseos", "", "standard", []string{"rhel-9-for-x86_64-baseos-rpms", "rhel-9-for-x86_64-appstream-rpms"}, false},
		{"major-lock", "9.8", "cpe:/o:redhat:enterprise_linux:9.8::baseos", "9", "standard", []string{"rhel-9-for-x86_64-baseos-rpms"}, false},
		{"eus", "9.4", "cpe:/o:redhat:enterprise_linux:9::baseos", "9.4", "eus", []string{"rhel-9-for-x86_64-baseos-eus-rpms", "rhel-9-for-x86_64-appstream-eus-rpms"}, false},
		{"e4s", "8.6", "cpe:/o:redhat:enterprise_linux:8::baseos", "8.6", "e4s", []string{"rhel-8-for-x86_64-baseos-e4s-rpms"}, false},
		{"mixed-streams", "9.4", "cpe:/o:redhat:enterprise_linux:9::baseos", "9.4", "", []string{"rhel-9-for-x86_64-baseos-rpms", "rhel-9-for-x86_64-appstream-eus-rpms"}, false},
		{"eus-without-lock", "9.4", "cpe:/o:redhat:enterprise_linux:9::baseos", "", "", []string{"rhel-9-for-x86_64-baseos-eus-rpms"}, false},
		{"lock-conflict", "9.8", "cpe:/o:redhat:enterprise_linux:9::baseos", "9.4", "", []string{"rhel-9-for-x86_64-baseos-rpms"}, false},
		{"foreign-product", "9.8", "cpe:/o:rocky:rocky:9", "", "", []string{"rhel-9-for-x86_64-baseos-rpms"}, false},
		{"missing-repositories", "9.8", "cpe:/o:redhat:enterprise_linux:9::baseos", "", "", nil, false},
		{"failed-native-reader", "9.8", "cpe:/o:redhat:enterprise_linux:9::baseos", "", "", nil, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			platform := &inventoryv1.PlatformDetails{
				Cpe:            &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Value: test.cpe},
				ReleaseverLock: &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE},
				Repositories:   &inventoryv1.RepositoryObservation{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Ids: test.repositories, Backend: "dnf"},
			}
			if test.lock != "" {
				platform.ReleaseverLock = &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Value: test.lock}
			}
			if test.repositoriesFailed {
				platform.Repositories = &inventoryv1.RepositoryObservation{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_NATIVE_COMMAND_FAILURE}
			}
			encoded, err := proto.Marshal(&inventoryv1.NativeDetails{Platform: platform})
			if err != nil {
				t.Fatal(err)
			}
			got, err := rhelStream(encoded, test.release, "x86_64")
			if err != nil || got != test.want {
				t.Fatalf("stream = %q, %v; want %q", got, err, test.want)
			}
		})
	}
	if got, err := rhelStream(nil, "9.8", "x86_64"); err != nil || got != "" {
		t.Fatalf("historical missing evidence became a stream: %q, %v", got, err)
	}
}
