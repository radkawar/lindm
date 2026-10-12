package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/devlab"
	"lindm/internal/labhost"
	"lindm/internal/platform"
	"lindm/internal/vmlab"
)

func splitAssistance(host *labv1.LabHost, args []string) bool {
	if len(args) < 2 || args[1] != "assistance" || host.Transport != "ssh" || host.Runtime != "native" {
		return false
	}
	colocated := false
	for _, arg := range args[2:] {
		name, value, explicit := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		if strings.HasPrefix(arg, "-") && name == "colocated" {
			parsed, err := strconv.ParseBool(value)
			colocated = !explicit || err == nil && parsed
		}
	}
	return !colocated
}

// controllerAddress asks the kernel which local source address routes to the
// SSH destination. UDP connect selects a route without sending a packet.
func controllerAddress(ctx context.Context, alias, override string) (netip.Addr, error) {
	if override != "" {
		return assistanceControllerIPv4(override)
	}
	probe, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(probe, "ssh", "-G", "--", alias)
	output, err := command.Output()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("resolve SSH hostname: %w", err)
	}
	hostname := ""
	for line := range strings.SplitSeq(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "hostname" {
			hostname = fields[1]
			break
		}
	}
	if hostname == "" {
		return netip.Addr{}, errors.New("SSH configuration has no HostName")
	}
	connection, err := (&net.Dialer{}).DialContext(probe, "udp4", net.JoinHostPort(hostname, "22"))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("resolve controller route: %w", err)
	}
	local, ok := connection.LocalAddr().(*net.UDPAddr)
	closeErr := connection.Close()
	if !ok {
		return netip.Addr{}, errors.Join(errors.New("controller route is not UDP"), closeErr)
	}
	if closeErr != nil {
		return netip.Addr{}, closeErr
	}
	return assistanceControllerIPv4(local.IP.String())
}

func assistanceControllerIPv4(value string) (netip.Addr, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() {
		return netip.Addr{}, errors.New("controller address must be a routed specific IPv4 address")
	}
	return address, nil
}

func assistanceEnrollmentOptions(architecture, buildRepository string) (devlab.LoadAuthorityOptions, error) {
	architecture, err := labhost.NormalizeArchitecture(architecture)
	if err != nil {
		return devlab.LoadAuthorityOptions{}, err
	}
	return devlab.LoadAuthorityOptions{
		NativeEnrollmentArchitectures:    []string{architecture},
		NativeEnrollmentSourceRepository: buildRepository,
	}, nil
}

func runSplitAssistance(ctx context.Context, host *labv1.LabHost, architecture, buildRepository string, args []string, stdout, stderr io.Writer) (err error) {
	rebootPolicy := assistanceFlag(args, "reboot-policy")
	if err := validateRebootPolicyFlags(rebootPolicy, vmHolds(args), labhost.FlagValue(args, "name"), labhost.FlagValue(args, "scenarios")); err != nil {
		return err
	}
	address, err := controllerAddress(ctx, host.SshAlias, labhost.FlagValue(args, "controller-address"))
	if err != nil {
		return err
	}
	repository := labhost.FlagValue(args, "repo")
	if repository == "" {
		repository = "."
	}
	var enrollment devlab.LoadAuthorityOptions
	if vmHolds(args) {
		enrollment, err = assistanceEnrollmentOptions(architecture, buildRepository)
		if err != nil {
			return err
		}
	}
	root := ""
	var controller *vmlab.AssistanceController
	if name := labhost.FlagValue(args, "name"); name != "" {
		root, err = controllerDemoDirectory(name)
		if err != nil {
			return err
		}
		controller, err = vmlab.OpenPersistentAssistanceController(ctx, repository, labhost.FlagValue(args, "lindmd"), filepath.Join(root, "control-plane"), address, host.Name, enrollment)
	} else {
		controller, err = vmlab.OpenAssistanceController(ctx, repository, labhost.FlagValue(args, "lindmd"), address, host.Name, enrollment, rebootPolicy)
	}
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, controller.Close()) }()
	if vmHolds(args) {
		manifest, err := vmlab.LoadManifest(labhost.FlagValue(args, "manifest"))
		if err != nil {
			return err
		}
		advisories, err := devlab.HeldAdvisories(*platform.ForManifest(manifest.GetDistribution(), manifest.GetVersion()), manifest.GetArchitecture())
		if err != nil {
			return err
		}
		cache := labhost.FlagValue(args, "advisory-cache")
		if cache == "" {
			cache, err = controllerAdvisoryCache()
			if err != nil {
				return err
			}
		}
		if err := controller.Fixture.EnableAdvisories(ctx, advisories, cache); err != nil {
			return err
		}
	}
	private, err := os.MkdirTemp("", "lindm-assistance-controller-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(private)) }()
	handle := filepath.Join(private, "control-plane.json")
	if err := controller.WriteControlPlane(handle); err != nil {
		return err
	}
	args = labhost.SetFlag(args, "control-plane", handle)
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	watchContext, stopWatch := context.WithCancel(ctx)
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		if waitErr := controller.Fixture.Wait(watchContext); waitErr != nil && watchContext.Err() == nil {
			cancel(fmt.Errorf("controller fixture exited: %w", waitErr))
		}
	}()
	defer func() { stopWatch(); <-watched }()
	admin := strconv.Itoa(int(controller.Handle.Authority.AdminPort))
	relay := strconv.Itoa(int(controller.Handle.Relay.ListenerPort))
	run := labhost.RemoteRun{Host: host, Architecture: architecture, Repository: buildRepository, Args: args, Hold: vmHolds(args), Stdout: stdout, Stderr: stderr,
		ReverseForwards: []string{admin + ":127.0.0.1:" + admin, relay + ":" + address.String() + ":" + relay}}
	if run.Hold {
		run.OnHeld = func(ctx context.Context, marker []byte) error {
			var access vmlab.AssistanceHold
			if err := json.Unmarshal(marker, &access); err != nil {
				return err
			}
			defer func() { access.EnrollmentSecret, access.DesktopPassword = "", "" }()
			findings, err := controller.WaitDeviceFindings(ctx, access.DeviceID)
			if err != nil {
				return err
			}
			access.Findings = findings
			if root != "" {
				access.Persistent = true
				access.OwnerAccessFile = filepath.Join(root, "owner-access")
				access.ExistingAccount, err = persistentOwnerExists(root)
				if err != nil {
					return err
				}
			}
			if !access.ExistingAccount {
				enrollment, err := controller.Fixture.CreateConsoleEnrollment(ctx)
				if err != nil {
					return err
				}
				access.Username, access.EnrollmentSecret, access.ExpiresAt = "console-owner", enrollment.GetSecret(), enrollment.GetExpiresAt().AsTime().UTC()
				enrollment.Secret = ""
			}
			access.ConsoleOrigin = controller.Fixture.ConsoleOrigin
			if err := ctx.Err(); err != nil {
				return err
			}
			access.ControllerAddress = address.String()
			return writeAssistanceHold(stdout, labhost.FlagValue(args, "evidence"), &access)
		}
	}
	err = run.Run(ctx)
	if cause := context.Cause(ctx); cause != nil && !errors.Is(cause, context.Canceled) {
		err = errors.Join(err, cause)
	}
	return err
}

func controllerAdvisoryCache() (string, error) {
	cfg, err := labhost.Load()
	if err != nil {
		return "", err
	}
	for _, host := range cfg.Hosts {
		if host.Transport == "local" {
			work, err := labhost.ResolveWorkDirectory(host)
			if err != nil {
				return "", err
			}
			return filepath.Join(work, "advisory-cache"), nil
		}
	}
	return "", errors.New("held split assistance requires a configured local controller work directory for the advisory cache")
}

// publishAssistanceHeld is the private SSH control message. The remote lane
// never creates or receives the owner's console enrollment secret.
func publishAssistanceHeld(dir string, access *vmlab.AssistanceHold) (err error) {
	access.RemoteEvidenceDir = dir
	access.RespondBinary, err = os.Executable()
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".held-")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, os.Remove(file.Name()))
		}
	}()
	writeErr := json.NewEncoder(file).Encode(access)
	if err := errors.Join(writeErr, file.Close()); err != nil {
		return err
	}
	return os.Rename(file.Name(), filepath.Join(dir, "held"))
}

// publishDemoRegistration asks the SSH controller to record an organization
// device's public RHSM identity and returns only once it removed the marker,
// which it does after its demo state durably holds that identity. Nothing
// else is published while it waits.
func publishDemoRegistration(ctx context.Context, dir string, identity *labv1.RedHatRegistrationIdentity, interval time.Duration) error {
	data, err := protojson.Marshal(identity)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".registration-")
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return errors.Join(err, os.Remove(file.Name()))
	}
	marker := filepath.Join(dir, labhost.RegistrationMarker)
	if err := os.Rename(file.Name(), marker); err != nil {
		return errors.Join(err, os.Remove(file.Name()))
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if _, err := os.Lstat(marker); errors.Is(err, os.ErrNotExist) {
			return nil
		} else if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("controller did not record Red Hat registration %s %s: %w", identity.GetRunName(), identity.GetConsumerUuid(), ctx.Err())
		case <-ticker.C:
		}
	}
}
