//go:build linux

package actionprovider

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func nvmeActionFixture(method agentv1.SanitizeMethod, controllerWide bool) *agentv1.SanitizeAction {
	return &agentv1.SanitizeAction{
		Target: &agentv1.StorageTarget{IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL, Serial: "test-controller", Wwn: "eui.1200000000000034", SizeBytes: 4 << 20},
		Method: method,
		NvmeScope: &agentv1.NVMeSanitizeScope{
			NamespaceId:    1,
			ControllerWide: controllerWide,
			Identity: &agentv1.NVMeSanitizeIdentity{
				Basis:              agentv1.NvmeIdentityBasis_NVME_IDENTITY_BASIS_NAMESPACE_NID,
				VendorId:           0x1b36,
				SubsystemVendorId:  0x1234,
				ControllerSerial:   "test-controller",
				ControllerModel:    "disposable NVMe fixture",
				ControllerFirmware: "1.0",
				NamespaceSizeBytes: 4 << 20,
				LbaDataSizeShift:   9,
			},
		},
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
		func(c, _ []byte) { c[78]++ },    // Controller change.
		func(c, _ []byte) { c[328] = 0 }, // Sanitize capability change.
		func(_, n []byte) { n[33] = 1 },  // Deallocation behavior change.
	} {
		c, n := nvmeControllerFixture(), nvmeNamespaceFixture()
		mutate(c, n)
		after, err := nvmePlan(action, 1, c, n, inventory, inventory)
		if err != nil || proto.Equal(before, after) {
			t.Fatalf("changed native binding not observed: %v", err)
		}
	}
	// The FLBAS index is not approved: the plan carries the privileged
	// Identify's index for Format NVM, and the namespace digest binds it.
	if before.GetLbaFormat() != 0 {
		t.Fatalf("plan format index = %d", before.GetLbaFormat())
	}
	sameSize := nvmeNamespaceFixture()
	sameSize[25], sameSize[26], sameSize[134] = 1, 1, 9
	reformatted, err := nvmePlan(action, 1, controller, sameSize, inventory, inventory)
	if err != nil || reformatted.GetLbaFormat() != 1 || bytes.Equal(reformatted.GetIdentifyNamespaceSha256(), before.GetIdentifyNamespaceSha256()) {
		t.Fatalf("same-size format index not carried by the plan: %v %v", reformatted, err)
	}
	for _, mutate := range []func([]byte){
		func(n []byte) { n[25], n[26], n[134] = 1, 1, 12 },           // Changed data size.
		func(n []byte) { n[25], n[26], n[132], n[134] = 1, 1, 8, 9 }, // Metadata.
		func(n []byte) { n[29] = 1 },                                 // Protection information.
		func(n []byte) { n[25], n[26], n[134] = 1, 0x11, 9 },         // Extended LBA format.
	} {
		n := nvmeNamespaceFixture()
		mutate(n)
		if _, err := nvmePlan(action, 1, controller, n, inventory, inventory); err == nil {
			t.Fatal("approved size/shift admitted a changed or unsupported LBA format")
		}
	}
	for _, mutate := range []func(*agentv1.SanitizeAction){
		func(a *agentv1.SanitizeAction) { a.NvmeScope.NamespaceId = 2 },
		func(a *agentv1.SanitizeAction) { a.Target.Serial = "other-controller" },
		func(a *agentv1.SanitizeAction) { a.Target.Wwn = "eui.0000000000000001" },
		func(a *agentv1.SanitizeAction) { a.Target.SizeBytes++ },
		func(a *agentv1.SanitizeAction) { a.NvmeScope.Identity = nil },
		func(a *agentv1.SanitizeAction) { a.NvmeScope.Identity.Basis = 0 },
		func(a *agentv1.SanitizeAction) {
			a.NvmeScope.Identity.Basis = agentv1.NvmeIdentityBasis_NVME_IDENTITY_BASIS_CONTROLLER_SERIAL_NSID
		},
		func(a *agentv1.SanitizeAction) { a.NvmeScope.Identity.VendorId++ },
		func(a *agentv1.SanitizeAction) { a.NvmeScope.Identity.SubsystemVendorId++ },
		func(a *agentv1.SanitizeAction) { a.NvmeScope.Identity.ControllerSerial = "other-controller" },
		func(a *agentv1.SanitizeAction) { a.NvmeScope.Identity.ControllerModel = "other-model" },
		func(a *agentv1.SanitizeAction) { a.NvmeScope.Identity.ControllerFirmware = "2.0" },
		func(a *agentv1.SanitizeAction) { a.NvmeScope.Identity.NamespaceSizeBytes++ },
		func(a *agentv1.SanitizeAction) { a.NvmeScope.Identity.LbaDataSizeShift++ },
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
		scope := nvmeActionFixture(method, nvmeSanitizeCommand(method) != 0).GetNvmeScope()
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
	scope := nvmeActionFixture(agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_FORMAT_USER_DATA, false).GetNvmeScope()
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

func TestNVMePlanRejectsNativeIdentityMutation(t *testing.T) {
	action := nvmeActionFixture(agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_FORMAT_USER_DATA, false)
	inventory := nvmeNamespaceListFixture(1)
	for _, mutate := range []func([]byte, []byte){
		func(c, _ []byte) { c[0]++ },
		func(c, _ []byte) { c[2]++ },
		func(c, _ []byte) { c[4] = 'X' },
		func(c, _ []byte) { c[24] = 'X' },
		func(c, _ []byte) { c[64] = '2' },
		func(_, n []byte) { binary.LittleEndian.PutUint64(n[:8], 16384) },
		func(_, n []byte) {
			binary.LittleEndian.PutUint64(n[:8], 4096)
			binary.LittleEndian.PutUint64(n[8:16], 4096)
			n[130] = 10
		},
	} {
		controller, namespace := nvmeControllerFixture(), nvmeNamespaceFixture()
		mutate(controller, namespace)
		if _, err := nvmePlan(action, 1, controller, namespace, inventory, inventory); !errors.Is(err, ErrConflict) {
			t.Fatalf("mutated native identity accepted: %v", err)
		}
	}
}

func TestNVMeIdentityBasisRequiresExactNativeEvidence(t *testing.T) {
	controllerData := nvmeControllerFixture()
	copy(controllerData[4:24], "lindm-lab-0          ")
	copy(controllerData[24:64], "QEMU NVMe Ctrl                          ")
	controller, err := parseNVMeController(controllerData)
	if err != nil {
		t.Fatal(err)
	}
	const fallback = "nvme.1b36-6c696e646d2d6c61622d30-51454d55204e564d65204374726c-00000001"
	for _, tc := range []struct {
		name   string
		absent bool
		wwn    string
		serial string
		nsid   uint32
		basis  agentv1.NvmeIdentityBasis
	}{
		{"namespace NID", false, "eui.1200000000000034", "lindm-lab-0", 1, agentv1.NvmeIdentityBasis_NVME_IDENTITY_BASIS_NAMESPACE_NID},
		{"kernel discarded bogus NID", false, fallback, "lindm-lab-0", 1, agentv1.NvmeIdentityBasis_NVME_IDENTITY_BASIS_CONTROLLER_SERIAL_NSID},
		{"absent NIDs", true, fallback, "lindm-lab-0", 1, agentv1.NvmeIdentityBasis_NVME_IDENTITY_BASIS_CONTROLLER_SERIAL_NSID},
		{"absent NIDs and WWN", true, "", "lindm-lab-0", 1, agentv1.NvmeIdentityBasis_NVME_IDENTITY_BASIS_CONTROLLER_SERIAL_NSID},
		{"raw NID without kernel evidence", false, "", "lindm-lab-0", 1, 0},
		{"serial mismatch", false, fallback, "different", 1, 0},
		{"NSID mismatch", false, fallback, "lindm-lab-0", 2, 0},
		{"wrong NID", false, "eui.1200000000000035", "lindm-lab-0", 1, 0},
		{"noncanonical fallback", false, "nvme.1B36-6c696e646d2d6c61622d30-51454d55204e564d65204374726c-00000001", "lindm-lab-0", 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			namespaceData := nvmeNamespaceFixture()
			if tc.absent {
				clear(namespaceData[104:128])
			}
			namespace, err := parseNVMeNamespace(namespaceData)
			if err != nil {
				t.Fatal(err)
			}
			target := &agentv1.StorageTarget{IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL, Serial: tc.serial, Wwn: tc.wwn, SizeBytes: 4 << 20}
			basis, err := nvmeIdentityBasis(target, tc.nsid, controller, namespace)
			if tc.basis == 0 {
				if !errors.Is(err, ErrConflict) {
					t.Fatalf("unbound native identity accepted: %v", err)
				}
			} else if err != nil || basis != tc.basis {
				t.Fatalf("identity basis: %v %v, want %v", basis, err, tc.basis)
			}
		})
	}
}
