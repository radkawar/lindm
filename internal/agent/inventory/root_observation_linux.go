// SPDX-License-Identifier: Apache-2.0

//go:build linux

package inventory

import (
	"context"
	"os"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/types/known/timestamppb"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/agent/actionprovider"
)

// CollectRootObservation reads public inventory through privileged read-only
// interfaces. The executor supplies and rechecks the current boot identity.
// No key material or execution authority is included.
func CollectRootObservation(ctx context.Context, bootID string) *inventoryv1.RootObservation {
	return collectRootObservation(ctx, bootID, rootObservationSources())
}

// rootObservationSources are the native readers of the sandboxed root helper.
func rootObservationSources() detailSources {
	return detailSources{
		readFile: readDetailFile, readDir: readDetailDir, stat: os.Stat, run: runNative,
		openBlock: openStorageBlock, nvmeScope: actionprovider.ReadNVMeSanitizeScope,
	}
}

func collectRootObservation(ctx context.Context, bootID string, sources detailSources) *inventoryv1.RootObservation {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	// Root projections perform native reads themselves, including ARM SMBIOS.
	// The network collector uses the opposite setting to defer privileged reads.
	sources.rootObservation = false
	result := &inventoryv1.RootObservation{StartedAt: timestamppb.Now(), BootId: bootID}
	cpu, cpuErr := sources.file(ctx, "/proc/cpuinfo")
	result.Cpu = collectCPU(ctx, sources, cpu, cpuErr)
	if status := detailCategoryStatus(result.Cpu); status != success {
		err := errInvalid
		if status == capacity {
			err = errCapacity
		}
		result.Cpu = collectCPU(ctx, sources, nil, err)
	}
	if err := protovalidate.Validate(result.Cpu); err != nil {
		result.Cpu = collectCPU(ctx, sources, nil, errInvalid)
	}
	result.HardwareSerial = sources.text(ctx, "/sys/class/dmi/id/product_serial")
	result.Firmware = collectFirmware(ctx, sources)
	if err := ctx.Err(); err != nil {
		result.Storage = &inventoryv1.StorageDetails{Status: statusFor(err)}
	} else {
		result.Storage = collectStorage(ctx, sources)
	}
	if status := detailCategoryStatus(result.Storage); status != success {
		result.Storage = &inventoryv1.StorageDetails{Status: status}
	}
	if err := protovalidate.Validate(result.Storage); err != nil {
		result.Storage = &inventoryv1.StorageDetails{Status: invalid}
	}
	result.FinishedAt = timestamppb.Now()
	return result
}
