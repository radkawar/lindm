// SPDX-License-Identifier: Apache-2.0

package advisory

import (
	"strings"

	"google.golang.org/protobuf/proto"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// rhelStream requires corroborating native product and enabled-repository
// evidence. An absent repository, entitlement, or release lock is not inferred.
func rhelStream(encoded []byte, release, architecture string) (string, error) {
	var details inventoryv1.NativeDetails
	if err := proto.Unmarshal(encoded, &details); err != nil {
		return "", err
	}
	platform := details.GetPlatform()
	if platform.GetCpe().GetStatus() != inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS || platform.GetRepositories().GetStatus() != inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS {
		return "", nil
	}
	major, _, _ := strings.Cut(release, ".")
	cpe := strings.Split(platform.GetCpe().GetValue(), ":")
	if len(cpe) < 5 || cpe[0] != "cpe" || cpe[1] != "/o" || cpe[2] != "redhat" || (cpe[4] != major && cpe[4] != release) {
		return "", nil
	}
	if cpe[3] != "enterprise_linux" && cpe[3] != "rhel_eus" && cpe[3] != "rhel_e4s" {
		return "", nil
	}
	stream := ""
	baseOS := false
	prefix := "rhel-" + major + "-for-" + architecture + "-"
	for _, id := range platform.GetRepositories().GetIds() {
		kind := ""
		isBase := false
		switch id {
		case prefix + "baseos-rpms":
			kind, isBase = "standard", true
		case prefix + "appstream-rpms":
			kind = "standard"
		case prefix + "baseos-eus-rpms":
			kind, isBase = "eus", true
		case prefix + "appstream-eus-rpms":
			kind = "eus"
		case prefix + "baseos-e4s-rpms":
			kind, isBase = "e4s", true
		case prefix + "appstream-e4s-rpms":
			kind = "e4s"
		default:
			continue
		}
		if stream != "" && stream != kind {
			return "", nil
		}
		stream = kind
		baseOS = baseOS || isBase
	}
	if !baseOS || (cpe[3] == "rhel_eus" && stream != "eus") || (cpe[3] == "rhel_e4s" && stream != "e4s") {
		return "", nil
	}
	lock := platform.GetReleaseverLock()
	if lock.GetStatus() == inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS {
		if lock.GetValue() != release && (stream != "standard" || lock.GetValue() != major) {
			return "", nil
		}
	} else if stream != "standard" || lock.GetStatus() != inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE {
		return "", nil
	}
	if stream != "standard" && !strings.Contains(release, ".") {
		return "", nil
	}
	return stream, nil
}
