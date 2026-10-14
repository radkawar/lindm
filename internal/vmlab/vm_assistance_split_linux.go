// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/devlab"
)

// AssistanceControlPlane is private provisioning material, not a qualification
// record. Only the controller owns the server and its disposable database.
type AssistanceControlPlane struct {
	Authority         *devlab.ControlPlaneHandle `json:"authority"`
	Delegation        json.RawMessage            `json:"delegation"`
	Relay             assistanceRelayEvidence    `json:"relay"`
	ControllerAddress string                     `json:"controller_address"`
	LabHost           string                     `json:"lab_host"`
	LindmdSHA256      string                     `json:"lindmd_sha256"`
}

func (h *AssistanceControlPlane) forwardedTURNURL() string {
	return fmt.Sprintf("turn:localhost:%d?transport=tcp", h.Relay.ListenerPort)
}

// AssistanceController owns the workstation half of an SSH-native assistance
// run. Close follows remote teardown, so guest cleanup can still use the API.
type AssistanceController struct {
	Fixture *devlab.AuthorityFixture
	Handle  *AssistanceControlPlane
	control *vmControlPlane
}

func OpenAssistanceController(ctx context.Context, repository, binary string, address netip.Addr, host string, enrollment devlab.LoadAuthorityOptions, rebootPolicy bool) (*AssistanceController, error) {
	return openAssistanceController(ctx, repository, binary, "", address, host, enrollment, rebootPolicy)
}

// OpenPersistentAssistanceController reopens the same database, accounts and
// listeners before reconnecting the named remote VM.
func OpenPersistentAssistanceController(ctx context.Context, repository, binary, stateDir string, address netip.Addr, host string, enrollment devlab.LoadAuthorityOptions) (*AssistanceController, error) {
	return openAssistanceController(ctx, repository, binary, stateDir, address, host, enrollment, false)
}

func openAssistanceController(ctx context.Context, repository, binary, stateDir string, address netip.Addr, host string, enrollment devlab.LoadAuthorityOptions, rebootPolicy bool) (_ *AssistanceController, err error) {
	var fixture *devlab.AuthorityFixture
	if stateDir == "" {
		fixture, err = devlab.OpenSplitDeviceActionAuthorityFixture(ctx, repository, binary, address, enrollment)
	} else {
		fixture, err = devlab.OpenPersistentSplitFixture(ctx, repository, binary, stateDir, address, enrollment)
	}
	if err != nil {
		return nil, err
	}
	controller := &AssistanceController{Fixture: fixture}
	defer func() {
		if err != nil {
			err = errors.Join(err, controller.Close())
		}
	}()
	var delegation *agentv1.UpdateExecutionTrustRequest
	if rebootPolicy {
		delegation, err = fixture.ConfigureServiceDispatch(ctx)
	} else {
		delegation, err = fixture.ConfigureDeviceActions(ctx)
	}
	if err != nil {
		return nil, err
	}
	assistance, err := fixture.AssistanceConfiguration()
	if err != nil {
		return nil, err
	}
	if assistance == nil {
		assistance, err = devlab.ReserveAssistanceRelay(address.String(), address.String())
	}
	if err != nil {
		return nil, err
	}
	assistance.PolicyCeiling = assistanceFullPolicy()
	roles := assistanceQualificationRoles()
	if err := fixture.ConfigureAssistance(ctx, assistance, roles); err != nil {
		return nil, err
	}
	controller.control, err = openVMControlPlane(ctx, repository, fixture)
	if err != nil {
		return nil, err
	}
	if err := ensureAssistanceAuthority(ctx, controller.control, delegation); err != nil {
		return nil, err
	}
	authority, err := fixture.ExportControlPlane(ctx, "assistance-lane")
	if err != nil {
		return nil, err
	}
	encoded, err := protojson.Marshal(delegation)
	if err != nil {
		return nil, err
	}
	digest, err := dispatchFileDigest(binary)
	if err != nil {
		return nil, err
	}
	relay := assistance.GetRelay()
	controller.Handle = &AssistanceControlPlane{Authority: authority, Delegation: encoded, ControllerAddress: address.String(), LabHost: host, LindmdSHA256: digest,
		Relay: assistanceRelayEvidence{ListenerAddress: relay.GetListener().GetAddress(), ListenerPort: relay.GetListener().GetPort(), RelayAddress: relay.GetRelayAddress(), PortMin: relay.GetRelayPortMin(), PortMax: relay.GetRelayPortMax(), URLs: relay.GetUrls(), GuestRoute: fmt.Sprintf("guest -> QEMU user NAT on %s -> LAN -> controller %s (device %s; TURN UDP/TCP %d)", host, address, authority.DeviceOrigin, relay.GetListener().GetPort())}}
	return controller, nil
}

func (c *AssistanceController) Close() error {
	if c.Handle != nil && c.Handle.Authority != nil {
		c.Handle.Authority.ClearCredentials()
	}
	return errors.Join(c.control.Close(context.Background()), c.Fixture.Close())
}

func (c *AssistanceController) WaitDeviceFindings(ctx context.Context, deviceID string) (*devlab.DeviceFindingCounts, error) {
	return waitAssistanceFindings(ctx, c.Fixture, deviceID)
}

func waitAssistanceFindings(ctx context.Context, fixture *devlab.AuthorityFixture, deviceID string) (_ *devlab.DeviceFindingCounts, err error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	session, err := fixture.OpenOwnerSession(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		err = errors.Join(err, session.Close(cleanup))
	}()
	return devlab.WaitDeviceFindings(ctx, session, deviceID, 10*time.Minute)
}

// WriteControlPlane publishes a single-use private handle for SSH staging.
func (c *AssistanceController) WriteControlPlane(path string) (err error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	defer c.Handle.Authority.ClearCredentials()
	return json.NewEncoder(file).Encode(c.Handle)
}

// ReadAssistanceControlPlane consumes and removes the staged private handle.
func ReadAssistanceControlPlane(path string) (_ *AssistanceControlPlane, err error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close(), os.Remove(path)) }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 1<<20 {
		return nil, errors.New("control-plane handle must be a private bounded regular file")
	}
	var handle AssistanceControlPlane
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&handle); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("control-plane handle has trailing data")
	}
	if handle.Authority == nil {
		return nil, errors.New("control-plane handle has no authority")
	}
	return &handle, nil
}

func openAssistanceFixture(ctx context.Context, options VMAssistanceOptions, architecture string) (_ *devlab.AuthorityFixture, _ *agentv1.UpdateExecutionTrustRequest, _ assistanceRelayEvidence, err error) {
	if handle := options.ControlPlane; handle != nil {
		delegation := new(agentv1.UpdateExecutionTrustRequest)
		if err := protojson.Unmarshal(handle.Delegation, delegation); err != nil {
			return nil, nil, assistanceRelayEvidence{}, err
		}
		var fixture *devlab.AuthorityFixture
		if options.FixtureDir == "" {
			fixture, err = devlab.ConnectAuthorityFixture(ctx, handle.Authority)
		} else {
			fixture, err = devlab.ConnectPersistentAuthorityFixture(ctx, handle.Authority, options.FixtureDir)
		}
		return fixture, delegation, handle.Relay, err
	}
	var fixture *devlab.AuthorityFixture
	if options.FixtureDir != "" {
		enrollment := devlab.LoadAuthorityOptions{}
		if options.Hold != nil {
			enrollment.NativeEnrollmentArchitectures = []string{architecture}
			enrollment.NativeEnrollmentSourceRepository = VMBuildRepository(options.Repository, options.BuildRepository)
		}
		fixture, err = devlab.OpenPersistentFixture(ctx, options.Repository, options.LindmdBinary, options.FixtureDir, enrollment)
	} else if options.Hold != nil {
		fixture, err = devlab.OpenEnrollmentConsoleAuthorityFixture(ctx, options.Repository, VMBuildRepository(options.Repository, options.BuildRepository), options.LindmdBinary, []string{architecture}, "")
	} else {
		fixture, err = devlab.OpenDeviceActionAuthorityFixture(ctx, options.Repository, options.LindmdBinary)
	}
	if err != nil {
		return nil, nil, assistanceRelayEvidence{}, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, fixture.Close())
		}
	}()
	var delegation *agentv1.UpdateExecutionTrustRequest
	if options.RebootPolicy != nil {
		delegation, err = fixture.ConfigureServiceDispatch(ctx)
	} else {
		delegation, err = fixture.ConfigureDeviceActions(ctx)
	}
	if err != nil {
		return nil, nil, assistanceRelayEvidence{}, err
	}
	assistance, err := fixture.AssistanceConfiguration()
	if err != nil {
		return nil, nil, assistanceRelayEvidence{}, err
	}
	if assistance == nil {
		assistance, err = devlab.ReserveAssistanceRelay("127.0.0.1", options.RelayAddress)
	}
	if err != nil {
		return nil, nil, assistanceRelayEvidence{}, err
	}
	assistance.PolicyCeiling = assistanceFullPolicy()
	roles := assistanceQualificationRoles()
	if err := fixture.ConfigureAssistance(ctx, assistance, roles); err != nil {
		return nil, nil, assistanceRelayEvidence{}, err
	}
	relay := assistance.GetRelay()
	return fixture, delegation, assistanceRelayEvidence{ListenerAddress: relay.GetListener().GetAddress(), ListenerPort: relay.GetListener().GetPort(), RelayAddress: relay.GetRelayAddress(), PortMin: relay.GetRelayPortMin(), PortMax: relay.GetRelayPortMax(), URLs: relay.GetUrls(), GuestRoute: "guest localhost -> 10.0.2.2 (QEMU user networking) -> host 127.0.0.1"}, nil
}

func ensureAssistanceAuthority(ctx context.Context, control *vmControlPlane, delegation *agentv1.UpdateExecutionTrustRequest) error {
	current, err := control.executionAuthority(ctx)
	if err != nil {
		return err
	}
	if current.GetDelegation() != nil {
		return nil
	}
	return control.applyExecutionAuthority(ctx, delegation, 1, 1, 0)
}
