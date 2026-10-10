//go:build linux

package inventory

import (
	"context"
	_ "embed"
	"io"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// dnfConfigProbe uses only installed DNF4 configuration APIs. Its output is
// canonical protobuf JSON, not a parallel host/platform transport schema.
//
//go:embed platform_dnf.py
var dnfConfigProbe string

func failedPlatform(status inventoryv1.CollectionStatus) *inventoryv1.PlatformDetails {
	return &inventoryv1.PlatformDetails{
		Cpe:            &inventoryv1.ObservedString{Status: status},
		ReleaseverLock: &inventoryv1.ObservedString{Status: status},
		Repositories:   &inventoryv1.RepositoryObservation{Status: status},
	}
}

func parsePlatform(data []byte) *inventoryv1.PlatformDetails {
	result := new(inventoryv1.PlatformDetails)
	if err := protojson.Unmarshal(data, result); err != nil {
		return failedPlatform(invalid)
	}
	if err := protovalidate.Validate(result); err != nil {
		return failedPlatform(invalid)
	}
	return result
}

func collectPlatform(ctx context.Context, sources detailSources) *inventoryv1.PlatformDetails {
	var parsed *inventoryv1.PlatformDetails
	status := sources.run(ctx, backend{
		name: "dnf4-config", path: "/usr/bin/python3",
		args: []string{"-I", "-c", dnfConfigProbe},
	}, func(reader io.Reader) inventoryv1.CollectionStatus {
		data, err := io.ReadAll(io.LimitReader(reader, (128<<10)+1))
		if len(data) > 128<<10 {
			return capacity
		}
		if err != nil {
			return statusFor(err)
		}
		// Bounded EOF has been reached. Native diagnostics or failure take
		// precedence over malformed/empty output; no arbitrary text is retained.
		parsed = parsePlatform(data)
		return success
	})
	if status != success {
		parsed = failedPlatform(status)
	}
	release, err := loadOSRelease(ctx, sources.readFile)
	parsed.Cpe = observed(release["CPE_NAME"], err)
	return parsed
}
