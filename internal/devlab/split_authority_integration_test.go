// SPDX-License-Identifier: Apache-2.0

//go:build integration

package devlab

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestSplitAuthorityExportConnect(t *testing.T) {
	binary, repository := nativeServer(t)
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	var device netip.Addr
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && validateSplitDevice(prefix.Addr()) == nil {
			device = prefix.Addr()
			break
		}
	}
	if !device.IsValid() {
		t.Skip("split authority requires a host non-loopback IPv4 address")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	controller, err := OpenSplitDeviceActionAuthorityFixture(ctx, repository, binary, device, LoadAuthorityOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := controller.Close(); err != nil {
			t.Error(err)
		}
	}()
	admin, err := netip.ParseAddrPort(controller.AdminAddress)
	if err != nil || admin.Addr() != netip.MustParseAddr("127.0.0.1") {
		t.Fatal("split admin listener is not loopback-only")
	}
	deviceListener, err := netip.ParseAddrPort(controller.DeviceAddress)
	if err != nil || deviceListener.Addr() != device || controller.DeviceOrigin != "https://"+controller.DeviceAddress {
		t.Fatal("split device listener or signed origin does not use selected host address")
	}
	handle, err := controller.ExportControlPlane(ctx, "remote-lane-owner")
	if err != nil {
		t.Fatal(err)
	}
	if handle.WebAuthnCounter != 1 || len(handle.Password) == 0 || len(handle.WebAuthnPrivateKey) == 0 {
		t.Fatal("export did not finish lane account enrollment before handoff")
	}
	encoded, err := json.Marshal(handle)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	handle.ClearCredentials()
	var remoteHandle ControlPlaneHandle
	if err := json.Unmarshal(encoded, &remoteHandle); err != nil {
		t.Fatal(err)
	}
	connected, err := ConnectAuthorityFixture(ctx, &remoteHandle)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := connected.Close(); err != nil {
			t.Error(err)
		}
	}()
	if len(remoteHandle.Password) != 0 || len(remoteHandle.WebAuthnPrivateKey) != 0 || len(remoteHandle.WebAuthnCredentialID) != 0 || remoteHandle.WebAuthnCounter != 0 {
		t.Fatal("connected fixture retained transferred credentials")
	}
	if connected.ConsoleOrigin != controller.ConsoleOrigin || connected.DeviceOrigin != controller.DeviceOrigin || connected.DatabaseName != controller.DatabaseName {
		t.Fatal("connected fixture changed controller identity")
	}
	owner, err := connected.OpenOwnerSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if owner.AccountID == controller.local.owner.id || owner.AccountID != remoteHandle.AccountID {
		t.Error("connected fixture borrowed controller owner identity")
	}
	if err := owner.Close(ctx); err != nil {
		t.Fatal(err)
	}
	approval, err := OpenApprovalSession(ctx, "", connected)
	if err != nil {
		t.Fatal(err)
	}
	if approval.session.AccountID == owner.AccountID || approval.session.AccountID == controller.local.approver.id {
		t.Error("connected fixture borrowed an existing approver identity")
	}
	if err := approval.Close(ctx); err != nil {
		t.Fatal(err)
	}
	material, err := connected.ReadAgentFixture(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(material.ExecutionRootJSON, remoteHandle.ExecutionRootJSON) || !bytes.Equal(material.BootstrapEnvelope, remoteHandle.BootstrapEnvelope) {
		t.Fatal("connected fixture changed signed provisioning material")
	}
	clear(remoteHandle.ExecutionRootJSON)
	clear(remoteHandle.BootstrapEnvelope)
	clear(material.ExecutionRootJSON)
	clear(material.BootstrapEnvelope)
	if _, err := connected.ReadAgentFixture(ctx); err != nil {
		t.Fatalf("caller mutation changed connected trust: %v", err)
	}
	acceptance, err := connected.CreateAcceptanceEnrollment(ctx, "remote-browser-owner", "owner")
	if err != nil {
		t.Fatal(err)
	}
	acceptance.Secret = ""
	console, err := connected.CreateConsoleEnrollment(ctx)
	if err != nil {
		t.Fatal(err)
	}
	console.Secret = ""
	if err := controller.disableExportedAccounts(); err != nil {
		t.Fatal(err)
	}
	if retired, err := connected.OpenOwnerSession(ctx); err == nil {
		if err := retired.Close(ctx); err != nil {
			t.Error(err)
		}
		t.Fatal("controller teardown left exported lane account enabled")
	}
	if err := connected.Close(); err != nil {
		t.Fatal(err)
	}
	controllerOwner, err := controller.OpenOwnerSession(ctx)
	if err != nil {
		t.Fatalf("connected Close stopped controller: %v", err)
	}
	if err := controllerOwner.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
