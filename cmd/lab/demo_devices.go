// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	adminv1 "lindm/gen/lindm/admin/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/agent/nativeexec"
	"lindm/internal/demolab"
	"lindm/internal/labexec"
	"lindm/internal/labhost"
	"lindm/internal/vmlab"
)

func (r *demoRun) runDevice(ctx context.Context, bound *labv1.DemoBinding, credential string, forward bool, ready func(*vmlab.AssistanceHold) error) (err error) {
	var device *demolab.Device
	for i := range r.spec.Devices {
		if r.spec.Devices[i].Config.GetKey() == bound.Key {
			device = &r.spec.Devices[i]
			break
		}
	}
	if device == nil {
		return errors.New("bound demo device missing from spec")
	}
	private, err := os.MkdirTemp(r.root, ".handoff-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(private)) }()
	authority, err := r.controller.Fixture.ExportControlPlane(ctx, "demo-"+bound.Key)
	if err != nil {
		return err
	}
	defer authority.ClearCredentials()
	handle := *r.controller.Handle
	handle.Authority = authority
	handle.LabHost = bound.Host.GetName()
	controlPath := filepath.Join(private, "control-plane.json")
	if err := publishDemoJSON(controlPath, &handle, 0600); err != nil {
		return err
	}
	instructions, err := r.enrollmentInstructions(ctx)
	if err != nil {
		return err
	}
	install, err := r.installScript(ctx, instructions, device.Release.Key)
	if err != nil {
		return err
	}
	input := &vmlab.DemoDeviceInput{Hostname: bound.Device.GetHostname(), Desktop: bound.Device.GetRole() == labv1.DemoRole_DEMO_ROLE_DESKTOP, Assistance: bound.Device.GetAssistance(), TPMBind: bound.Device.GetTpmBind(), InstallScript: install, ProvisioningCommand: instructions.GetProvisioningCommand(), ResumeCommand: instructions.GetResumeCommand(), Token: demoToken(r.access, bound.Device.GetProvisioningToken())}
	inputPath := filepath.Join(private, "device.json")
	if err := publishDemoJSON(inputPath, input, 0600); err != nil {
		return err
	}
	input.Token = ""
	work := bound.Host.GetWorkDirectory()
	if bound.Host.GetTransport() == "local" {
		work, err = labhost.ResolveWorkDirectory(bound.Host)
		if err != nil {
			return err
		}
	}
	// RemoteRun resolves host work paths and relocates only authenticated
	// manifests and the two one-use handoffs, never firmware paths.
	args := []string{
		"vm", "assistance", "-hold", "-name", bound.DemoName, "-demo-parent", r.options.name,
		"-manifest", device.ManifestPath, "-repo", r.options.repository, "-build-repo", r.options.build,
		"-lab", r.options.lab, "-lindmd", r.options.lindmd, "-evidence", filepath.Join(r.options.evidence, bound.Key),
		"-control-plane", controlPath, "-demo-device", inputPath, "-work-dir", work,
		"-golden-cache", r.options.golden, "-cache", r.options.cache,
		"-storage-bus", "virtio-scsi", "-architecture", device.Architecture, "-tpm-boot",
	}
	firmware := bound.Device.GetFirmware()
	for _, pair := range [][2]string{{"firmware-code", firmware.GetCode()}, {"firmware-vars", firmware.GetVars()}, {"firmware-package", firmware.GetPackage()}, {"firmware-version", firmware.GetVersion()}} {
		if pair[1] != "" {
			args = labhost.SetFlag(args, pair[0], pair[1])
		}
	}
	args = labhost.SetFlag(args, "secure-boot", strconv.FormatBool(firmware.GetSecureBoot()))
	if device.Release.Lab.Entitlement {
		args = labhost.SetFlag(args, "redhat-token-file", r.options.redhatToken)
	}
	if bound.Host.GetTransport() == "ssh" {
		arch, err := labhost.NormalizeArchitecture(device.Manifest.GetArchitecture())
		if err != nil {
			return err
		}
		run := labhost.RemoteRun{Host: bound.Host, Architecture: arch, Repository: r.options.build, Args: args, Hold: true, BatchCredential: credential, Stdout: r.stdout, Stderr: r.stderr}
		// The worker continues only after this records its registration.
		run.OnRegistration = func(_ context.Context, marker []byte) error {
			return r.recordRegistrationMarker(bound.Key, marker)
		}
		if forward {
			admin, relay := strconv.Itoa(int(authority.AdminPort)), strconv.Itoa(int(handle.Relay.ListenerPort))
			run.ReverseForwards = []string{admin + ":127.0.0.1:" + admin, relay + ":" + handle.ControllerAddress + ":" + relay}
		}
		run.OnHeld = func(_ context.Context, data []byte) error {
			var access vmlab.AssistanceHold
			if err := json.Unmarshal(data, &access); err != nil {
				return err
			}
			return ready(&access)
		}
		return run.Run(ctx)
	}
	root, err := labhost.DemoDirectory(work, bound.DemoName)
	if err != nil {
		return err
	}
	args = labhost.SetFlag(args, "demo-root", root)
	slots, err := labhost.OpenSlots(bound.Host)
	if err != nil {
		return err
	}
	if err := slots.AdmitDisk(ctx, 1, r.stderr); err != nil {
		return err
	}
	ctx = context.WithValue(ctx, demoDeviceHeldKey{}, ready)
	ctx = context.WithValue(ctx, demoDeviceRegisteredKey{}, func(_ context.Context, identity *labv1.RedHatRegistrationIdentity) error {
		return r.recordRedHatRegistration(bound.Key, identity)
	})
	return slots.RunBatchWorker(ctx, credential, func(ctx context.Context) error { return runVMAssistance(ctx, args[2:], r.stdout, r.stderr) })
}

func (r *demoRun) installScript(ctx context.Context, instructions *adminv1.GetEnrollmentInstructionsResponse, platform string) (string, error) {
	data, err := (protojson.MarshalOptions{EmitUnpopulated: true}).Marshal(instructions)
	if err != nil {
		return "", err
	}
	input, err := json.Marshal(struct {
		Instructions json.RawMessage `json:"instructions"`
		Platform     string          `json:"platform"`
	}{data, platform})
	if err != nil {
		return "", err
	}
	output := nativeexec.NewBuffer(1 << 20)
	if err := labexec.Run(ctx, labexec.Command{Path: "node", Args: []string{"web/acceptance/demo-install.mjs"}, Dir: r.options.build, Stdin: bytes.NewReader(input), Stdout: output, Stderr: r.stderr, Timeout: time.Minute}); err != nil {
		return "", fmt.Errorf("render customer enrollment installer: %w", err)
	}
	if output.Truncated() || output.Len() == 0 {
		return "", errors.New("customer installer output is empty or exceeds bound")
	}
	return output.String(), nil
}

func (r *demoRun) enrollmentInstructions(ctx context.Context) (_ *adminv1.GetEnrollmentInstructionsResponse, err error) {
	owner, err := r.controller.Fixture.OpenOwnerSession(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, closeDemoSession(owner)) }()
	response, err := owner.Admin.GetEnrollmentInstructions(ctx, connect.NewRequest(&adminv1.GetEnrollmentInstructionsRequest{}))
	if err != nil {
		return nil, err
	}
	return response.Msg, nil
}

func (r *demoRun) verifyDeviceGroup(ctx context.Context, bound *labv1.DemoBinding, deviceID string) (err error) {
	owner, err := r.controller.Fixture.OpenOwnerSession(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, closeDemoSession(owner)) }()
	page := ""
	for {
		response, err := owner.Admin.ListDeviceGroups(ctx, connect.NewRequest(&adminv1.ListDeviceGroupsRequest{PageSize: 100, PageToken: page}))
		if err != nil {
			return err
		}
		for _, group := range response.Msg.GetGroups() {
			if group.GetId() != bound.Device.GetGroup() {
				continue
			}
			for _, id := range group.GetDeviceIds() {
				if id == deviceID {
					return nil
				}
			}
			return fmt.Errorf("device %s was not provisioned into its declared static group", bound.Key)
		}
		page = response.Msg.GetNextPageToken()
		if page == "" {
			return errors.New("declared organization static group is missing")
		}
	}
}

func (r *demoRun) writeReady() error {
	devices := make(map[string]*vmlab.AssistanceHold, len(r.access.Devices))
	for key, access := range r.access.Devices {
		public := *access
		public.EnrollmentSecret, public.DesktopPassword = "", ""
		devices[key] = &public
	}
	if err := publishDemoJSON(filepath.Join(r.options.evidence, "ready.json"), devices, 0400); err != nil {
		return err
	}
	admin := r.controller.Handle.Authority.AdminPort
	relay := r.controller.Handle.Relay.ListenerPort
	if _, err := fmt.Fprintf(r.stdout, "Organization demo %s is running; Ctrl-C stops all processes and keeps enrolled state.\nConsole: %s\nRemote console: ssh -N -L %d:127.0.0.1:%d -L %d:%s:%d <controller-host>\nOwner: %s/enroll as %s, enroll once; original secret and role-account enrollments: %s (0400). Existing owner sessions remain subject to ordinary expiry.\n", r.options.name, r.access.ConsoleOrigin, admin, admin, relay, r.controller.Handle.ControllerAddress, relay, r.access.ConsoleOrigin, r.access.Username, filepath.Join(r.root, "owner-access")); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(r.stdout, "Fresh owner and role enrollments are issued at first readiness and expire after 1h; resume never renews them. Original owner enrollment expiry: %s. Role expiries are in owner-access. To replace an expired unused role enrollment, explicitly reset that account at %s/accounts; the product returns a fresh enrollment.\n", r.access.EnrollmentExpiresAt.UTC().Format(time.RFC3339), r.access.ConsoleOrigin); err != nil {
		return err
	}
	for _, bound := range r.state.Bindings {
		if bound.Device.GetRole() != labv1.DemoRole_DEMO_ROLE_DESKTOP {
			continue
		}
		access := r.access.Devices[bound.Key]
		binary, dir, host := r.options.lab, filepath.Join(r.options.evidence, bound.Key), "<this-host>"
		if bound.Host.GetTransport() == "ssh" {
			binary, dir, host = access.RespondBinary, access.RemoteEvidenceDir, bound.Host.GetSshAlias()
		}
		if _, err := fmt.Fprintf(r.stdout, "Desktop %s (%s): ssh %s %s vm assistance-respond -evidence %s <%s>\n", bound.Key, access.DeviceID, host, binary, dir, strings.Join(vmlab.AssistanceRespondActions, "|")); err != nil {
			return err
		}
	}
	token := ""
	if r.options.redhatToken != "" {
		token = " -redhat-token-file " + r.options.redhatToken
	}
	_, err := fmt.Fprintf(r.stdout, "Destroy after stop: %s demo -name %s -destroy -repo %s -build-repo %s%s\nEvidence: %s\n", r.options.lab, r.options.name, r.options.repository, r.options.build, token, r.options.evidence)
	return err
}
