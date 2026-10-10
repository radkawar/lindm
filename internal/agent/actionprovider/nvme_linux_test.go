//go:build linux

package actionprovider

import (
	"encoding/binary"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func nvmeActionFixture(method agentv1.SanitizeMethod, controllerWide bool) *agentv1.SanitizeAction {
	return &agentv1.SanitizeAction{
		Target:    &agentv1.StorageTarget{Serial: "test-controller", Wwn: "eui.1200000000000034", SizeBytes: 4 << 20},
		Method:    method,
		NvmeScope: &agentv1.NVMeSanitizeScope{NamespaceId: 1, ControllerWide: controllerWide},
	}
}

func TestNVMePlanBindsExactControllerNamespaceAndInventory(t *testing.T) {
	action := nvmeActionFixture(agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_FORMAT_USER_DATA, false)
	controller, namespace, inventory := nvmeControllerFixture(), nvmeNamespaceFixture(), nvmeNamespaceListFixture(1)
	before, err := nvmePlan(action, 1, controller, namespace, inventory, inventory)
	if err != nil || before.GetControllerId() != 7 || before.GetControllerSerial() != action.GetTarget().GetSerial() || !proto.Equal(before.GetScope(), action.GetNvmeScope()) {
		t.Fatalf("native plan: %v %v", before, err)
	}
	for _, mutate := range []func([]byte, []byte){
		func(c, _ []byte) { c[64] = '2' }, // Firmware change.
		func(c, _ []byte) { c[78]++ },     // Controller change.
		func(c, _ []byte) { c[328] = 0 },  // Sanitize capability change.
		func(_, n []byte) { n[33] = 1 },   // Deallocation behavior change.
	} {
		c, n := nvmeControllerFixture(), nvmeNamespaceFixture()
		mutate(c, n)
		after, err := nvmePlan(action, 1, c, n, inventory, inventory)
		if err != nil || proto.Equal(before, after) {
			t.Fatalf("changed native binding not observed: %v", err)
		}
	}
	for _, mutate := range []func(*agentv1.SanitizeAction){
		func(a *agentv1.SanitizeAction) { a.NvmeScope.NamespaceId = 2 },
		func(a *agentv1.SanitizeAction) { a.Target.Serial = "other-controller" },
		func(a *agentv1.SanitizeAction) { a.Target.Wwn = "eui.0000000000000001" },
		func(a *agentv1.SanitizeAction) { a.Target.SizeBytes++ },
	} {
		wrong := proto.CloneOf(action)
		mutate(wrong)
		if _, err := nvmePlan(wrong, 1, controller, namespace, inventory, inventory); !errors.Is(err, ErrConflict) {
			t.Fatalf("changed exact media accepted: %v", err)
		}
	}
}

func TestNVMeMethodScopeRequiresAdvertisedSupportAndExactApproval(t *testing.T) {
	controller, err := parseNVMeController(nvmeControllerFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []agentv1.SanitizeMethod{
		agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_FORMAT_USER_DATA,
		agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_FORMAT_CRYPTO_ERASE,
		agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_SANITIZE_BLOCK_ERASE,
		agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_SANITIZE_CRYPTO_ERASE,
	} {
		scope := &agentv1.NVMeSanitizeScope{NamespaceId: 1, ControllerWide: nvmeSanitizeCommand(method) != 0}
		if err := nvmeMethodScope(method, scope, controller, []uint32{1}); err != nil {
			t.Fatalf("advertised method %s: %v", method, err)
		}
		wrongScope := proto.CloneOf(scope)
		wrongScope.ControllerWide = !wrongScope.ControllerWide
		if err := nvmeMethodScope(method, wrongScope, controller, []uint32{1}); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("scope silently widened/narrowed for %s: %v", method, err)
		}
		absent := controller
		absent.oacs, absent.fna, absent.sanicap = 0, 0, 0
		if err := nvmeMethodScope(method, scope, absent, []uint32{1}); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("unadvertised %s accepted: %v", method, err)
		}
		qualified := &agentv1.QualifiedActionTarget{AllowDiscard: true, AllowOverwrite: true}
		if nativeSanitizeAllowed(qualified, method) {
			t.Fatalf("generic method approval authorized native %s", method)
		}
		qualified.NativeSanitizeMethods = []agentv1.SanitizeMethod{method}
		if !nativeSanitizeAllowed(qualified, method) {
			t.Fatalf("exact native method not qualified: %s", method)
		}
	}
	for _, method := range []agentv1.SanitizeMethod{0, 1, 2, 99} {
		if nativeSanitizeMethod(method) || nativeSanitizeAllowed(&agentv1.QualifiedActionTarget{NativeSanitizeMethods: []agentv1.SanitizeMethod{method}}, method) {
			t.Fatalf("non-native/unknown method accepted: %v", method)
		}
	}
}

func TestNVMeControllerWideNeverTouchesUnapprovedNamespaces(t *testing.T) {
	controller, err := parseNVMeController(nvmeControllerFixture())
	if err != nil {
		t.Fatal(err)
	}
	controller.namespaces = 2
	scope := &agentv1.NVMeSanitizeScope{NamespaceId: 1}
	// A genuinely namespace-local format can coexist with another namespace.
	if err := nvmeMethodScope(agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_FORMAT_USER_DATA, scope, controller, []uint32{1, 2}); err != nil {
		t.Fatal(err)
	}
	for _, fna := range []byte{1, 2, 3} {
		controller.fna = fna
		if err := nvmeMethodScope(agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_FORMAT_USER_DATA, scope, controller, []uint32{1, 2}); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("all-namespace FNA=%d accepted local scope: %v", fna, err)
		}
		scope.ControllerWide = true
		if err := nvmeMethodScope(agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_FORMAT_USER_DATA, scope, controller, []uint32{1, 2}); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("unapproved second namespace accepted FNA=%d: %v", fna, err)
		}
		if err := nvmeMethodScope(agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_FORMAT_USER_DATA, scope, controller, []uint32{1}); err != nil {
			t.Fatalf("sole namespace controller-wide format rejected: %v", err)
		}
		scope.ControllerWide = false
	}
	scope.ControllerWide = true
	if err := nvmeMethodScope(agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_SANITIZE_BLOCK_ERASE, scope, controller, []uint32{1, 2}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("sanitize affected unapproved namespace: %v", err)
	}
}

func TestNVMePlanRejectsInactiveAndIncompleteNamespaceScope(t *testing.T) {
	action := nvmeActionFixture(agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_SANITIZE_BLOCK_ERASE, true)
	controller := nvmeControllerFixture()
	binary.LittleEndian.PutUint16(controller[256:258], 10)
	binary.LittleEndian.PutUint32(controller[516:520], 256)
	active, allocated := nvmeNamespaceListFixture(1), nvmeNamespaceListFixture(1, 2)
	if _, err := nvmePlan(action, 1, controller, nvmeNamespaceFixture(), active, allocated); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("detached namespace omitted: %v", err)
	}
	// QEMU's NN is a namespace ceiling, not the number currently allocated.
	// Its Namespace Management support permits authoritative allocated listing.
	if _, err := nvmePlan(action, 1, controller, nvmeNamespaceFixture(), active, active); err != nil {
		t.Fatalf("complete single allocated namespace rejected: %v", err)
	}
	binary.LittleEndian.PutUint16(controller[256:258], 2)
	if _, err := nvmePlan(action, 1, controller, nvmeNamespaceFixture(), active, active); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unprovable inactive namespace inventory accepted: %v", err)
	}
}
