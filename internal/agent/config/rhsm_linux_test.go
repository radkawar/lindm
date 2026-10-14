// SPDX-License-Identifier: Apache-2.0

//go:build linux

package config

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/platform"
)

func entitledRPM(vendor platform.VendorRepository, architecture string) *resourcev1.RpmRepository {
	ids := vendor.Entitled.NativeIDs[architecture]
	return &resourcev1.RpmRepository{
		NativeId: ids[0], Location: &resourcev1.RpmRepository_RhsmManaged{RhsmManaged: true}, RequirePackageSignature: true,
		AdditionalRepositories: []*resourcev1.RpmAdditionalRepository{{NativeId: ids[1], Location: &resourcev1.RpmAdditionalRepository_RhsmManaged{RhsmManaged: true}}},
	}
}

func TestEntitledMetadataTrustCannotWidenRegistryIDs(t *testing.T) {
	for _, key := range []string{"rhel-9", "rhel-10"} {
		row, _ := platform.Lookup(key)
		vendor := row.VendorRepositories[0]
		for _, architecture := range row.Architectures {
			valid := entitledRPM(vendor, architecture)
			if !RPMMetadataTrusted(row, valid) {
				t.Fatalf("%s %s exact entitled source refused", key, architecture)
			}
			for name, change := range map[string]func(*resourcev1.RpmRepository){
				"wrong primary":    func(r *resourcev1.RpmRepository) { r.NativeId = "unapproved" },
				"wrong additional": func(r *resourcev1.RpmRepository) { r.AdditionalRepositories[0].NativeId = "unapproved" },
				"debug source":     func(r *resourcev1.RpmRepository) { r.NativeId += "-debug" },
				"EUS source": func(r *resourcev1.RpmRepository) {
					r.NativeId = strings.Replace(r.NativeId, "-baseos-", "-baseos-eus-", 1)
				},
				"missing AppStream": func(r *resourcev1.RpmRepository) { r.AdditionalRepositories = nil },
				"extra repo": func(r *resourcev1.RpmRepository) {
					r.AdditionalRepositories = append(r.AdditionalRepositories, &resourcev1.RpmAdditionalRepository{NativeId: "unapproved", Location: &resourcev1.RpmAdditionalRepository_RhsmManaged{RhsmManaged: true}})
				},
				"mixed architectures": func(r *resourcev1.RpmRepository) {
					r.NativeId = strings.Replace(r.NativeId, architecture, "foreign", 1)
				},
				"generic base URL": func(r *resourcev1.RpmRepository) {
					r.Location = &resourcev1.RpmRepository_BaseUrls{BaseUrls: &resourcev1.RepositoryURLs{Urls: []string{"https://cdn.redhat.com/content/"}}}
				},
				"mixed base URL": func(r *resourcev1.RpmRepository) {
					r.AdditionalRepositories[0].Location = &resourcev1.RpmAdditionalRepository_BaseUrls{BaseUrls: &resourcev1.RepositoryURLs{Urls: []string{"https://cdn.redhat.com/content/"}}}
				},
				"mixed signed escape": func(r *resourcev1.RpmRepository) {
					r.RequireMetadataSignature = true
					r.AdditionalRepositories[0].Location = &resourcev1.RpmAdditionalRepository_Metalink{Metalink: "https://attacker.invalid/metalink"}
				},
				"unsigned packages": func(r *resourcev1.RpmRepository) { r.RequirePackageSignature = false },
			} {
				t.Run(key+"/"+architecture+"/"+name, func(t *testing.T) {
					invalid := proto.CloneOf(valid)
					change(invalid)
					if RPMMetadataTrusted(row, invalid) {
						t.Fatal("entitled marker widened source trust")
					}
				})
			}
			for _, other := range []string{"rhel-8", "fedora-44", "rocky-9", "almalinux-10", "rhel-9", "rhel-10"} {
				if other == key {
					continue
				}
				foreign, _ := platform.Lookup(other)
				if RPMMetadataTrusted(foreign, valid) {
					t.Fatalf("%s entitled IDs accepted on %s", key, other)
				}
			}
			if RPMMetadataTrusted(nil, valid) {
				t.Fatal("entitlement admitted without identified release")
			}
		}
	}
}
