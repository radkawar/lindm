//go:build linux

package inventory

import (
	"context"
	_ "embed"
	"io"
	"os"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/agent/dnf"
)

// dnfConfigProbe uses installed DNF4 or libdnf5 configuration APIs. Its output
// is canonical protobuf JSON, not a parallel host/platform transport schema.
//
//go:embed platform_dnf.py
var dnfConfigProbe string

func failedPlatform(status inventoryv1.CollectionStatus) *inventoryv1.PlatformDetails {
	return &inventoryv1.PlatformDetails{
		Cpe:            &inventoryv1.ObservedString{Status: status},
		ReleaseverLock: &inventoryv1.ObservedString{Status: status},
		Repositories:   &inventoryv1.RepositoryObservation{Status: status},
		Releasever:     &inventoryv1.ObservedString{Status: status},
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

func collectDNFPlatform(ctx context.Context, sources detailSources) (result *inventoryv1.PlatformDetails) {
	path, err := dnf.Executable(sources.stat)
	if err != nil {
		return failedPlatform(statusFor(err))
	}
	// DNF5 initializes logging even for --version. A private transient directory
	// avoids modifying native state or depending on a writable inherited HOME.
	logDirectory, err := os.MkdirTemp("", "lindm-dnf-version-")
	if err != nil {
		return failedPlatform(statusFor(err))
	}
	defer func() {
		if err := os.RemoveAll(logDirectory); err != nil {
			result = failedPlatform(statusFor(err))
		}
	}()
	var manager dnf.Manager
	status := sources.run(ctx, backend{name: "dnf-version", path: path, args: dnf.VersionArgs(logDirectory)}, func(reader io.Reader) inventoryv1.CollectionStatus {
		data, err := io.ReadAll(io.LimitReader(reader, (64<<10)+1))
		if len(data) > 64<<10 {
			return capacity
		}
		if err != nil {
			return statusFor(err)
		}
		manager, err = dnf.ParseVersion(data)
		if err != nil {
			return invalid
		}
		return success
	})
	if status != success {
		return failedPlatform(status)
	}
	var parsed *inventoryv1.PlatformDetails
	status = sources.run(ctx, backend{
		name: string(manager.Kind) + "-config", path: "/usr/bin/python3",
		args: []string{"-I", "-c", dnfConfigProbe, string(manager.Kind)},
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
	return parsed
}

func collectPlatform(ctx context.Context, sources detailSources) *inventoryv1.PlatformDetails {
	parsed := collectDNFPlatform(ctx, sources)
	release, err := loadOSRelease(ctx, sources.readFile)
	parsed.Cpe = observed(release["CPE_NAME"], err)
	return parsed
}
