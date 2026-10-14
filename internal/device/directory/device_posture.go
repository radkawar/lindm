// SPDX-License-Identifier: Apache-2.0

package directory

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/device/core"
	"lindm/internal/device/devicedb"
)

// rootEncryptions classifies each row's root filesystem from its current
// generation's latest host observation. Rows without one stay UNKNOWN. Details
// are read through one batch and decoded one row at a time.
func rootEncryptions(ctx context.Context, q *devicedb.Queries, rows []devicedb.SearchDevicesRow) ([]adminv1.DeviceRootEncryption, error) {
	states := make([]adminv1.DeviceRootEncryption, len(rows))
	generations := make([]uuid.UUID, 0, len(rows))
	positions := make([]int, 0, len(rows))
	for i, row := range rows {
		states[i] = adminv1.DeviceRootEncryption_DEVICE_ROOT_ENCRYPTION_UNKNOWN
		if row.CurrentGenerationID != nil {
			generations = append(generations, *row.CurrentGenerationID)
			positions = append(positions, i)
		}
	}
	if len(generations) == 0 {
		return states, nil
	}
	var failure error
	q.HostObservationDetails(ctx, generations).QueryRow(func(i int, details []byte, err error) {
		switch {
		case failure != nil, errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			failure = err
		default:
			states[positions[i]], failure = rootEncryption(details)
		}
	})
	return states, failure
}

// nativeStorageField is NativeDetails.storage; only that field is decoded.
var nativeStorageField = (&inventoryv1.NativeDetails{}).ProtoReflect().Descriptor().Fields().ByName("storage").Number()

// rootEncryption reads the agent's own classification of the block device
// mounted at "/" (see internal/agent/inventory storage collection). Missing or
// failed storage evidence, no observed root, an unclassified root or roots that
// disagree are UNKNOWN; NOT_ENCRYPTED needs the explicit "none" observation.
func rootEncryption(details []byte) (adminv1.DeviceRootEncryption, error) {
	unknown := adminv1.DeviceRootEncryption_DEVICE_ROOT_ENCRYPTION_UNKNOWN
	storage := new(inventoryv1.StorageDetails)
	for len(details) > 0 {
		number, kind, n := protowire.ConsumeTag(details)
		if n < 0 {
			return unknown, core.ErrInternalState
		}
		details = details[n:]
		if number == nativeStorageField && kind == protowire.BytesType {
			value, n := protowire.ConsumeBytes(details)
			if n < 0 {
				return unknown, core.ErrInternalState
			}
			// Repeated occurrences merge, exactly as a whole-message decode would.
			if err := (proto.UnmarshalOptions{Merge: true}).Unmarshal(value, storage); err != nil {
				return unknown, core.ErrInternalState
			}
			details = details[n:]
			continue
		}
		n = protowire.ConsumeFieldValue(number, kind, details)
		if n < 0 {
			return unknown, core.ErrInternalState
		}
		details = details[n:]
	}
	success := inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	if storage.GetStatus() != success {
		return unknown, nil
	}
	state := unknown
	for _, device := range storage.GetDevices() {
		if device.GetMountpoint().GetStatus() != success || device.GetMountpoint().GetValue() != "/" {
			continue
		}
		observed := unknown
		if device.GetEncryption().GetStatus() == success {
			switch device.GetEncryption().GetValue() {
			case "luks", "dm-crypt", "inherited-dm-crypt":
				observed = adminv1.DeviceRootEncryption_DEVICE_ROOT_ENCRYPTION_ENCRYPTED
			case "none":
				observed = adminv1.DeviceRootEncryption_DEVICE_ROOT_ENCRYPTION_NOT_ENCRYPTED
			}
		}
		if observed == unknown || (state != unknown && state != observed) {
			return unknown, nil
		}
		state = observed
	}
	return state, nil
}
