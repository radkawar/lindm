// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"errors"
	"time"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

// ListDeviceStorageTargets projects the current generation's published host
// observation. These candidates do not qualify or authorize native execution.
func (s *Service) ListDeviceStorageTargets(ctx context.Context, req *connect.Request[adminv1.ListDeviceStorageTargetsRequest]) (*connect.Response[adminv1.ListDeviceStorageTargetsResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_argument")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, core.MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := devicedb.New(tx)
	id, _ := uuid.Parse(req.Msg.GetDeviceId())
	if err := core.RequireDeviceScope(ctx, q, actor, identity.PermissionReadFleet, id); err != nil {
		return nil, core.MapErr(err)
	}
	device, err := q.GetDeviceDetail(ctx, id)
	if err != nil {
		return nil, core.MapErr(err)
	}
	response := &adminv1.ListDeviceStorageTargetsResponse{UnavailableReason: "device_action_inventory_unavailable"}
	var host devicedb.GetHostObservationRow
	details := new(inventoryv1.NativeDetails)
	now, err := core.DispatchClock(ctx, q)
	if err != nil {
		return nil, core.MapErr(err)
	}
	if device.CurrentGenerationID != nil {
		response.EnrollmentGeneration = device.CurrentGenerationID.String()
		host, err = q.GetHostObservation(ctx, *device.CurrentGenerationID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, core.MapErr(err)
		}
		if err == nil {
			response.HostSequence = uint64(host.Sequence)
			response.ReceivedAt = core.ProtoTime(host.ReceivedAt)
			response.ObservedAt = core.ProtoTime(host.FinishedAt)
			response.Fresh = ActionInventoryFresh(host, now)
			if len(host.Details) > 0 {
				if err := proto.Unmarshal(host.Details, details); err != nil {
					return nil, core.MapErr(core.ErrInternalState)
				}
				response.Targets, response.UnavailableReason = ObservedStorageTargets(details, req.Msg.GetActionKind())
				if req.Msg.GetActionKind() == "tpm2_bind" && response.UnavailableReason == "" && !core.TPM2BindSupported(host) {
					response.Targets, response.UnavailableReason = nil, "device_action_tpm2_binding_unsupported"
				}
				if req.Msg.GetActionKind() == "crypto_erase" {
					response.EphemeralMappings = EphemeralKeyMappings(details)
				}
			}
			if !response.Fresh {
				response.UnavailableReason = "device_action_inventory_stale"
			}
		}
	}
	if req.Msg.GetActionKind() == "sanitize" {
		response.RecoveryReadiness, err = s.RecoveryReadiness(ctx, host, details, req.Msg.GetRecoveryImageSha256(), now)
		if err != nil {
			return nil, core.MapErr(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	return core.NoStore(response), nil
}

// ActionInventoryMaxAge bounds how old the latest host inventory may be when a
// device action selects inventory facts. Host collection runs every 10 minutes,
// independently of the 60-second check-in, so a device that just checked in can
// still hold an inventory older than this.
const ActionInventoryMaxAge = 5 * time.Minute

func ActionInventoryFresh(host devicedb.GetHostObservationRow, now time.Time) bool {
	return host.ReceivedAt.Valid && !host.ReceivedAt.Time.After(now) && now.Sub(host.ReceivedAt.Time) <= ActionInventoryMaxAge
}

func storageString(value *inventoryv1.ObservedString) string {
	if value.GetStatus() != inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS {
		return ""
	}
	return value.GetValue()
}

func storageTarget(device *inventoryv1.BlockDevice, byName map[string]*inventoryv1.BlockDevice, diskSerials map[string]int) *agentv1.StorageTarget {
	success := inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	identity := device.GetIdentity()
	wwn, serial := storageString(identity.GetWwn()), storageString(identity.GetSerial())
	size := device.GetSizeBytes()
	if serial == "" || size.GetStatus() != success || size.GetValue() == 0 {
		return nil
	}
	luks := storageString(identity.GetLuksUuid())
	if wwn != "" {
		return &agentv1.StorageTarget{IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL, Wwn: wwn, Serial: serial, SizeBytes: size.GetValue(), LuksUuid: luks}
	}
	// Only an explicitly unavailable WWN can select the fallback. Failed,
	// historical or contradictory WWN observations cannot silently downgrade.
	unavailable := inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE
	if identity.GetWwn().GetStatus() != unavailable || identity.GetWwn().GetValue() != "" || storageString(device.GetType()) != "part" || !luksContainer(device) {
		return nil
	}
	if id, err := uuid.Parse(luks); err != nil || id == uuid.Nil {
		return nil
	}
	disk := byName[storageString(identity.GetBackingDisk())]
	diskIdentity := disk.GetIdentity()
	if storageString(disk.GetType()) != "disk" || storageString(diskIdentity.GetSerial()) != serial || diskSerials[serial] != 1 {
		return nil
	}
	if diskIdentity.GetWwn().GetStatus() != unavailable || diskIdentity.GetWwn().GetValue() != "" {
		return nil
	}
	diskSize := disk.GetSizeBytes()
	if diskSize.GetStatus() != success || diskSize.GetValue() < size.GetValue() {
		return nil
	}
	guid := storageString(identity.GetGptDiskGuid())
	if guid != storageString(diskIdentity.GetGptDiskGuid()) {
		return nil
	}
	if id, err := uuid.Parse(guid); err != nil || id == uuid.Nil {
		return nil
	}
	return &agentv1.StorageTarget{IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_SERIAL_GPT_LUKS, Serial: serial, SizeBytes: size.GetValue(), LuksUuid: luks, GptDiskGuid: guid, DiskSizeBytes: diskSize.GetValue()}
}

func luksContainer(device *inventoryv1.BlockDevice) bool {
	return storageString(device.GetFilesystem()) == "crypto_LUKS" || storageString(device.GetEncryption()) == "luks"
}

// Every descendant must positively report no encryption. Walking the observed
// parent graph also handles collectors that did not emit backing_disk metadata.
func unencryptedDisk(disk *inventoryv1.BlockDevice, devices []*inventoryv1.BlockDevice, byName map[string]*inventoryv1.BlockDevice) bool {
	if storageString(disk.GetType()) != "disk" {
		return false
	}
	for _, device := range devices {
		descendant := device == disk || storageString(device.GetIdentity().GetBackingDisk()) == disk.GetName()
		current := device
		for depth := 0; !descendant && current != nil && depth < len(devices); depth++ {
			current = byName[storageString(current.GetParent())]
			descendant = current == disk
		}
		if descendant && (storageString(device.GetEncryption()) != "none" || storageString(device.GetIdentity().GetLuksUuid()) != "" || luksContainer(device)) {
			return false
		}
	}
	return true
}

func ObservedStorageTargets(details *inventoryv1.NativeDetails, kind string) ([]*adminv1.DeviceStorageTarget, string) {
	success := inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	storage := details.GetStorage()
	if storage.GetStatus() != success || len(storage.GetDevices()) == 0 {
		return nil, "device_action_storage_unavailable"
	}
	if kind == "tpm2_bind" && !core.TPM2Available(details.GetTpm()) {
		return nil, "device_action_tpm2_unavailable"
	}
	byName := make(map[string]*inventoryv1.BlockDevice, len(storage.GetDevices()))
	diskSerials := make(map[string]int)
	for _, device := range storage.GetDevices() {
		if _, duplicate := byName[device.GetName()]; duplicate {
			return nil, "device_action_storage_identity_unavailable"
		}
		byName[device.GetName()] = device
		// Children inherit serials for target display and matching, but are not
		// additional physical identities for fallback uniqueness.
		if storageString(device.GetType()) == "disk" {
			if serial := storageString(device.GetIdentity().GetSerial()); serial != "" {
				diskSerials[serial]++
			}
		}
	}
	var targets []*adminv1.DeviceStorageTarget
	for _, device := range storage.GetDevices() {
		target := storageTarget(device, byName, diskSerials)
		if target == nil {
			continue
		}
		switch kind {
		case "escrow_rotate", "tpm2_bind", "crypto_erase":
			if !luksContainer(device) {
				continue
			}
			if id, err := uuid.Parse(target.GetLuksUuid()); err != nil || id == uuid.Nil {
				continue
			}
		case "sanitize":
			if target.GetIdentityBasis() != agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL || target.GetLuksUuid() != "" || !unencryptedDisk(device, storage.GetDevices(), byName) {
				continue
			}
		default:
			return nil, "device_action_storage_unavailable"
		}
		identity := device.GetIdentity()
		candidate := &adminv1.DeviceStorageTarget{Target: target, Name: device.GetName(), SizeBytes: target.GetSizeBytes(), Model: storageString(identity.GetModel()), Encryption: storageString(device.GetEncryption()), Mountpoint: storageString(device.GetMountpoint()), RootBacking: identity.GetRootBacking().GetStatus() == success && identity.GetRootBacking().GetValue()}
		if identity.GetNvme().GetStatus() == success {
			candidate.Nvme = identity.GetNvme().GetScope()
		}
		targets = append(targets, candidate)
	}
	if len(targets) == 0 {
		return nil, "device_action_storage_identity_unavailable"
	}
	return targets, ""
}

func RequireObservedStorageTargets(details *inventoryv1.NativeDetails, spec *agentv1.DeviceActionSpec) error {
	var kind string
	var requested []*agentv1.StorageTarget
	switch {
	case spec.GetEscrowRotate() != nil:
		kind, requested = "escrow_rotate", []*agentv1.StorageTarget{spec.GetEscrowRotate().GetTarget()}
	case spec.GetTpm2Bind() != nil:
		kind, requested = "tpm2_bind", []*agentv1.StorageTarget{spec.GetTpm2Bind().GetTarget()}
	case spec.GetCryptoErase() != nil:
		kind = "crypto_erase"
		requested = spec.GetCryptoErase().GetTargets()
		if spec.GetCryptoErase().GetTarget() != nil {
			requested = []*agentv1.StorageTarget{spec.GetCryptoErase().GetTarget()}
		}
	case spec.GetSanitize() != nil:
		kind, requested = "sanitize", []*agentv1.StorageTarget{spec.GetSanitize().GetTarget()}
	default:
		return nil
	}
	candidates, reason := ObservedStorageTargets(details, kind)
	if reason != "" {
		return rpcreason.Error(connect.CodeFailedPrecondition, reason)
	}
	mismatch := func() error {
		return rpcreason.Error(connect.CodeFailedPrecondition, "device_action_storage_target_mismatch")
	}
	for i, target := range requested {
		for _, previous := range requested[:i] {
			if proto.Equal(target, previous) {
				return mismatch()
			}
		}
		var matched *adminv1.DeviceStorageTarget
		for _, candidate := range candidates {
			if proto.Equal(target, candidate.GetTarget()) {
				if matched != nil {
					return mismatch()
				}
				matched = candidate
			}
		}
		if matched == nil {
			return mismatch()
		}
		if scope := spec.GetSanitize().GetNvmeScope(); scope != nil {
			// ControllerWide is explicitly approved effect scope, not an observed
			// identity fact. Native preflight still qualifies the entire effect.
			if matched.GetNvme() == nil || scope.GetNamespaceId() != matched.GetNvme().GetNamespaceId() || !proto.Equal(scope.GetIdentity(), matched.GetNvme().GetIdentity()) {
				return mismatch()
			}
		}
	}
	if core.LiveRootAction(spec) {
		containers := 0
		byName := make(map[string]*inventoryv1.BlockDevice, len(details.GetStorage().GetDevices()))
		for _, device := range details.GetStorage().GetDevices() {
			byName[device.GetName()] = device
		}
		for _, device := range details.GetStorage().GetDevices() {
			if luksContainer(device) {
				containers++
			}
			encryption := storageString(device.GetEncryption())
			if encryption == "" || encryption == "none" || luksContainer(device) {
				continue
			}
			// An encrypted mapping is covered only by its observed native LUKS
			// ancestor, or by an ancestor the agent natively proved to be a
			// plain mapping keyed from the kernel RNG on every activation (its
			// key is never stored and is destroyed at power-off). Unproven plain
			// dm-crypt and incomplete topology cannot disappear from a request
			// claiming the complete encrypted volume set.
			covered := false
			current := device
			for depth := 0; current != nil && depth < len(byName); depth++ {
				if luksContainer(current) || EphemeralKeyMapping(current) {
					covered = true
					break
				}
				current = byName[storageString(current.GetParent())]
			}
			if !covered {
				return rpcreason.Error(connect.CodeFailedPrecondition, "device_action_storage_target_set_mismatch")
			}
		}
		if len(requested) != len(candidates) || len(requested) != containers {
			return rpcreason.Error(connect.CodeFailedPrecondition, "device_action_storage_target_set_mismatch")
		}
	}
	return nil
}

// EphemeralKeyMapping reports the agent's native proof that a dm-crypt mapping
// is keyed from the kernel RNG on every activation; any other status, or an
// observation from an agent that predates the field, is not proof.
func EphemeralKeyMapping(device *inventoryv1.BlockDevice) bool {
	key := device.GetIdentity().GetEphemeralKey()
	return storageString(device.GetType()) == "crypt" && key.GetStatus() == inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS && key.GetValue()
}

// EphemeralKeyMappings names the proven ephemeral mappings of an observation.
func EphemeralKeyMappings(details *inventoryv1.NativeDetails) []string {
	var names []string
	for _, device := range details.GetStorage().GetDevices() {
		if EphemeralKeyMapping(device) {
			names = append(names, device.GetName())
		}
	}
	return names
}
