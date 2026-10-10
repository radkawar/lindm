//go:build linux

package actionprovider

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func nativeSanitizeMethod(method agentv1.SanitizeMethod) bool {
	switch method {
	case agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_FORMAT_USER_DATA,
		agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_FORMAT_CRYPTO_ERASE,
		agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_SANITIZE_BLOCK_ERASE,
		agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_SANITIZE_CRYPTO_ERASE:
		return true
	default:
		return false
	}
}

func nativeSanitizeAllowed(qualification *agentv1.QualifiedActionTarget, method agentv1.SanitizeMethod) bool {
	return nativeSanitizeMethod(method) && slices.Contains(qualification.GetNativeSanitizeMethods(), method)
}

func nvmeSanitizeCommand(method agentv1.SanitizeMethod) uint32 {
	switch method {
	case agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_SANITIZE_BLOCK_ERASE:
		return 2
	case agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_SANITIZE_CRYPTO_ERASE:
		return 4
	default:
		return 0
	}
}

func nvmeMethodScope(method agentv1.SanitizeMethod, scope *agentv1.NVMeSanitizeScope, controller nvmeController, allocated []uint32) error {
	if scope == nil || scope.GetNamespaceId() == 0 || scope.GetNamespaceId() == ^uint32(0) || !slices.Contains(allocated, scope.GetNamespaceId()) {
		return fmt.Errorf("%w: nvme_namespace_scope", ErrUnsupported)
	}
	var controllerWide bool
	switch method {
	case agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_FORMAT_USER_DATA:
		if controller.oacs&2 == 0 {
			return fmt.Errorf("%w: nvme_format_not_advertised", ErrUnsupported)
		}
		controllerWide = controller.fna&3 != 0
	case agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_FORMAT_CRYPTO_ERASE:
		if controller.oacs&2 == 0 || controller.fna&4 == 0 {
			return fmt.Errorf("%w: nvme_crypto_format_not_advertised", ErrUnsupported)
		}
		controllerWide = controller.fna&3 != 0
	case agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_SANITIZE_BLOCK_ERASE:
		if controller.sanicap&2 == 0 {
			return fmt.Errorf("%w: nvme_block_sanitize_not_advertised", ErrUnsupported)
		}
		controllerWide = true
	case agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_SANITIZE_CRYPTO_ERASE:
		if controller.sanicap&1 == 0 {
			return fmt.Errorf("%w: nvme_crypto_sanitize_not_advertised", ErrUnsupported)
		}
		controllerWide = true
	default:
		return ErrUnsupported
	}
	if scope.GetControllerWide() != controllerWide {
		return fmt.Errorf("%w: nvme_observed_scope_differs", ErrUnsupported)
	}
	// The ordinary offline-target gate protects precisely one namespace graph.
	// A controller/subsystem-wide effect is safe only if that graph is the sole
	// allocated namespace. Never erase another namespace merely because it is
	// on the same controller, or silently substitute a namespace-local method.
	if controllerWide && (len(allocated) != 1 || allocated[0] != scope.GetNamespaceId()) {
		return fmt.Errorf("%w: nvme_controller_has_other_namespaces", ErrUnsupported)
	}
	return nil
}

func nvmePlan(action *agentv1.SanitizeAction, nsid uint32, controllerData, namespaceData, activeData, allocatedData []byte) (*agentv1.NVMeSanitizePlan, error) {
	controller, err := parseNVMeController(controllerData)
	if err != nil {
		return nil, err
	}
	namespace, err := parseNVMeNamespace(namespaceData)
	if err != nil {
		return nil, err
	}
	active, err := parseNVMeNamespaceList(activeData)
	if err != nil {
		return nil, err
	}
	allocated, err := parseNVMeNamespaceList(allocatedData)
	if err != nil {
		return nil, err
	}
	if !slices.Equal(active, allocated) || uint32(len(allocated)) > controller.namespaces {
		return nil, fmt.Errorf("%w: nvme_inactive_namespace_scope", ErrUnsupported)
	}
	if controller.oacs&8 == 0 && uint32(len(allocated)) != controller.namespaces {
		return nil, fmt.Errorf("%w: nvme_namespace_inventory_incomplete", ErrUnsupported)
	}
	if action.GetNvmeScope().GetNamespaceId() != nsid || controller.serial != action.GetTarget().GetSerial() || namespace.size != action.GetTarget().GetSizeBytes() || !namespace.matchesWWN(action.GetTarget().GetWwn()) {
		return nil, fmt.Errorf("%w: nvme_exact_identity_changed", ErrConflict)
	}
	if err := nvmeMethodScope(action.GetMethod(), action.GetNvmeScope(), controller, allocated); err != nil {
		return nil, err
	}
	inventory := sha256.New()
	_, _ = inventory.Write(activeData)
	_, _ = inventory.Write(allocatedData)
	return &agentv1.NVMeSanitizePlan{
		Scope:                    proto.CloneOf(action.GetNvmeScope()),
		ControllerSerial:         controller.serial,
		ControllerModel:          controller.model,
		ControllerFirmware:       controller.firmware,
		ControllerId:             uint32(controller.id),
		Oacs:                     uint32(controller.oacs),
		Fna:                      uint32(controller.fna),
		Sanicap:                  controller.sanicap,
		AllocatedNamespaceIds:    allocated,
		IdentifyControllerSha256: controller.digest[:],
		IdentifyNamespaceSha256:  namespace.digest[:],
		NamespaceInventorySha256: inventory.Sum(nil),
	}, nil
}

// Read-only native capability/scope discovery. Callers own stable media identity
// resolution. Apply additionally requires openTarget's exclusive/off-root/
// off-target/recovery checks; this helper alone never authorizes destruction.
func (p *Provider) observeNVMe(ctx context.Context, spec *agentv1.DeviceActionSpec, target *targetHandle) (*agentv1.NVMeSanitizePlan, error) {
	action := spec.GetSanitize()
	if !nativeSanitizeAllowed(target.qualification, action.GetMethod()) || target.node.Type != "disk" || encryptedTree(target.node) {
		return nil, ErrUnsupported
	}
	nsid, err := nvmeNamespaceID(target.file)
	if err != nil {
		return nil, err
	}
	controllerData, err := p.nvmeAdmin(ctx, target.file, 6, 0, 1, nvmeIdentifyBytes)
	if err != nil {
		return nil, errors.Join(ErrUnsupported, err)
	}
	controller, err := parseNVMeController(controllerData)
	if err != nil {
		return nil, err
	}
	namespaceData, err := p.nvmeAdmin(ctx, target.file, 6, nsid, 0, nvmeIdentifyBytes)
	if err != nil {
		return nil, errors.Join(ErrUnsupported, err)
	}
	activeData, err := p.nvmeAdmin(ctx, target.file, 6, 0, 2, nvmeIdentifyBytes)
	if err != nil {
		return nil, errors.Join(ErrUnsupported, err)
	}
	// Without Namespace Management capability all NN namespaces must be
	// present in the active list. With it, read the allocated list as well so
	// detached namespaces cannot be omitted from subsystem-wide effects.
	allocatedData := activeData
	if controller.oacs&8 != 0 {
		allocatedData, err = p.nvmeAdmin(ctx, target.file, 6, 0, 0x10, nvmeIdentifyBytes)
		if err != nil {
			return nil, errors.Join(ErrUnsupported, err)
		}
	}
	plan, err := nvmePlan(action, nsid, controllerData, namespaceData, activeData, allocatedData)
	if err != nil {
		return nil, err
	}
	if controller.sanicap&7 != 0 {
		status, err := p.nvmeStatus(ctx, target.file)
		if err != nil {
			return nil, errors.Join(ErrUnsupported, err)
		}
		if status.status&7 == 2 || status.status&7 == 3 {
			return nil, fmt.Errorf("%w: nvme_prior_sanitize_unresolved", ErrUnsupported)
		}
	}
	return plan, nil
}
