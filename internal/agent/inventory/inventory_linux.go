//go:build linux

// Package inventory collects bounded local Linux evidence. It does not enroll a
// device, assert compliance, or establish a distribution's lifecycle qualification.
package inventory

import (
	"context"
	"fmt"
	"os"

	"buf.build/go/protovalidate"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// Collect returns actual host and native-package evidence. Collection failures
// are represented by typed statuses; a failed package attempt never has rows.
// An error indicates that the resulting evidence could not be validated.
func Collect(ctx context.Context) (*inventoryv1.NativeObservation, error) {
	host, release := collectHost(ctx, readHostFile)
	if host.OsId.Status != success || host.OsVersion.Status != success {
		release = nil
	}
	result := &inventoryv1.NativeObservation{
		Host:     host,
		Packages: collectPackages(ctx, release, os.Stat, runNative),
	}
	if err := protovalidate.Validate(result); err != nil {
		return nil, fmt.Errorf("validate native observation: %w", err)
	}
	return result, nil
}
