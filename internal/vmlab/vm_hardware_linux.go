//go:build linux

package vmlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// VMHardwareOptions selects disposable emulated hardware, never host devices.
// Nil Firmware selects legacy BIOS on x86; aarch64 requires explicit EFI files.
// Empty architecture/storage retain x86_64/virtio-blk. Empty accelerator selects
// KVM for the native architecture and TCG for a foreign architecture, without a
// fallback if the selected accelerator fails. ExtraDisks admits zero to four
// private 1 GiB disks. Desktop exposes only a private Unix VNC socket; it is not
// desktop installation or physical hardware qualification evidence.
type VMHardwareOptions struct {
	Architecture string
	Accelerator  string
	Firmware     *EncryptedFirmwareOptions
	TPM          bool
	StorageBus   string
	ExtraDisks   int
	Desktop      bool
	// AllowNetwork explicitly permits user-mode egress for signed package setup.
	// It never adds a host bridge or changes host firewall rules.
	AllowNetwork bool
	// Recovery boots reserve a separate controller before QEMU starts: q35's
	// root PCIe bus cannot accept the controller itself through QMP hotplug.
	recoveryTarget bool
	// Acceptance preserves vendor timers rather than quiescing inventory fixtures.
	stockAcceptance bool
	// dataLink adds nic1 on a lane-owned host-local L2 link to one peer guest.
	dataLink           *vmDataLink
	offlineRTCWaitUnit string
	// rootRepair is the release's registry Lab.RootPermissionsRepair; stock
	// acceptance guests keep the vendor mode.
	rootRepair []string
}

func (h *VMHardwareOptions) offlineRTCEnabled() bool {
	return h.offlineRTCWaitUnit != "" && !h.AllowNetwork && !h.stockAcceptance
}

// vmDataLink is a guest's second NIC on a host-local Unix datagram Ethernet
// link shared with exactly one other guest of the same lane. QEMU binds Local
// and sends frames to Remote; both lie in one lane-owned private directory, so
// concurrent lanes on a host never share a segment. It never creates a host
// bridge, tap device, route or firewall rule, and it works unchanged on remote
// lab hosts because both guests run on the same executing host.
type vmDataLink struct {
	MAC           string
	Local, Remote string
}

// sun_path holds 108 bytes including the terminator.
const maxUnixSocketPath = 107

func (l vmDataLink) validate() error {
	mac, err := net.ParseMAC(l.MAC)
	if err != nil || len(mac) != 6 || mac.String() != l.MAC || mac[0]&1 != 0 || mac[0]&2 == 0 {
		return errors.New("VM data link requires a lowercase locally administered unicast MAC")
	}
	for _, path := range []string{l.Local, l.Remote} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, ",\x00") || len(path) > maxUnixSocketPath {
			return errors.New("VM data link endpoints must be short clean absolute socket paths")
		}
	}
	if l.Local == l.Remote || filepath.Dir(l.Local) != filepath.Dir(l.Remote) {
		return errors.New("VM data link endpoints must be distinct sockets in one private link directory")
	}
	return nil
}

func resolveVMHardware(options *VMHardwareOptions, hostArch string) (VMHardwareOptions, error) {
	var h VMHardwareOptions
	if options != nil {
		h = *options
		if options.Firmware != nil {
			firmware := *options.Firmware
			h.Firmware = &firmware
		}
	}
	if h.Architecture == "" {
		h.Architecture = "x86_64"
	}
	if h.Architecture != "x86_64" && h.Architecture != "aarch64" {
		return h, errors.New("VM architecture must be x86_64 or aarch64")
	}
	native := (h.Architecture == "x86_64" && hostArch == "amd64") || (h.Architecture == "aarch64" && hostArch == "arm64")
	if h.Accelerator == "" {
		h.Accelerator = "tcg"
		if native {
			h.Accelerator = "kvm"
		}
	}
	if h.Accelerator != "kvm" && h.Accelerator != "tcg" {
		return h, errors.New("VM accelerator must be kvm or tcg")
	}
	if h.Accelerator == "kvm" && !native {
		return h, errors.New("KVM requires a native guest architecture; select tcg for cross-architecture emulation")
	}
	if h.StorageBus == "" {
		h.StorageBus = "virtio-blk"
	}
	switch h.StorageBus {
	case "virtio-blk", "virtio-scsi", "nvme", "sata":
	default:
		return h, errors.New("VM storage bus must be virtio-blk, virtio-scsi, nvme or sata")
	}
	if h.ExtraDisks < 0 || h.ExtraDisks > 4 {
		return h, errors.New("VM extra disks must be between zero and four")
	}
	if h.Architecture == "aarch64" && h.StorageBus == "sata" {
		// ArmVirtQemu (AAVMF) has no AHCI driver: the firmware lists no disk
		// and falls through to network boot, so the guest could never start.
		return h, errors.New("aarch64 AAVMF cannot boot from the SATA (AHCI) controller; use nvme, virtio-scsi or virtio-blk")
	}
	if h.Architecture == "aarch64" && h.Firmware == nil {
		return h, errors.New("aarch64 VM requires explicit pinned EFI firmware")
	}
	if h.Firmware != nil && (h.Firmware.Code == "" || h.Firmware.Vars == "" || h.Firmware.Package == "" || h.Firmware.Version == "") {
		return h, errors.New("VM EFI firmware requires code, variables, package and exact version")
	}
	if options != nil && options.dataLink != nil {
		link := *options.dataLink
		if err := link.validate(); err != nil {
			return h, err
		}
		h.dataLink = &link
	}
	return h, nil
}

func checkVMAcceleration(h VMHardwareOptions) error {
	if h.Accelerator != "kvm" {
		return nil
	}
	kvm, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("KVM access is required (no software fallback): %w", err)
	}
	return kvm.Close()
}

func (v *guestVM) prepareHardware(ctx context.Context) error {
	var err error
	if v.hardware.Firmware != nil {
		v.firmware, err = prepareEncryptedFirmware(ctx, v.dir, *v.hardware.Firmware)
		if err != nil {
			return err
		}
	}
	for i := range v.hardware.ExtraDisks {
		name := fmt.Sprintf("extra-%d.qcow2", i)
		if _, err := hostCommand(ctx, v.dir, "qemu-img", nil, "create", "-f", "qcow2", name, "1G"); err != nil {
			return err
		}
		if err := os.Chmod(filepath.Join(v.dir, name), 0600); err != nil {
			return err
		}
	}
	if !v.hardware.TPM {
		return nil
	}
	if err := os.Mkdir(filepath.Join(v.dir, "tpm"), 0700); err != nil {
		return err
	}
	v.tpm, err = startEncryptedProcess(ctx, v.dir, "swtpm", "socket", "--tpm2", "--tpmstate", "dir=tpm", "--ctrl", "type=unixio,path=tpm.sock,mode=0600", "--flags", "not-need-init")
	if err != nil {
		return err
	}
	ready, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		info, err := os.Lstat(filepath.Join(v.dir, "tpm.sock"))
		if err == nil {
			if info.Mode()&os.ModeSocket == 0 {
				return errors.New("swtpm control path is not a Unix socket")
			}
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect swtpm control socket: %w", err)
		}
		select {
		case <-ready.Done():
			return fmt.Errorf("swtpm readiness: %w", ready.Err())
		case <-v.tpm.done:
			return fmt.Errorf("swtpm exited before readiness: %s", v.tpm.log.diagnostic(v.dir))
		case <-ticker.C:
		}
	}
}

// configuredVMArguments uses JSON block nodes so filenames cannot become QEMU
// options. Only fixed, private relative paths appear in comma-delimited options.
func configuredVMArguments(h VMHardwareOptions, dir, port string, allowReboot bool) ([]string, error) {
	machine, cpu := "q35", "max"
	if h.Architecture == "aarch64" {
		machine = "virt"
	}
	if h.Accelerator == "kvm" {
		cpu = "host"
	}
	machine += ",accel=" + h.Accelerator
	if h.Architecture == "x86_64" && h.Firmware != nil && h.Firmware.SecureBoot {
		machine += ",smm=on"
	}
	args := []string{"-no-user-config", "-nodefaults", "-display", "none", "-serial", "unix:serial.sock,server=on,wait=off", "-monitor", "none", "-qmp", "unix:qmp.sock,server=on,wait=off", "-machine", machine, "-cpu", cpu, "-m", "2048", "-smp", "2"}
	if h.offlineRTCEnabled() {
		args = append(args, "-rtc", "base=utc,clock=host")
	}
	// Fresh UEFI variables/TPM state can require a firmware initialization reset.
	// Enforce a caller's no-reboot policy only after pinned SSH readiness.
	if !allowReboot && h.Firmware == nil {
		args = append(args, "-no-reboot")
	}
	if h.Firmware != nil {
		args = append(args, "-drive", "if=pflash,format=raw,unit=0,readonly=on,file=firmware-code.fd", "-drive", "if=pflash,format=raw,unit=1,file=nvram.fd")
		if h.Architecture == "x86_64" && h.Firmware.SecureBoot {
			args = append(args, "-global", "driver=cfi.pflash01,property=secure,value=on")
		}
	}
	blocks := []map[string]any{
		{"driver": "file", "node-name": "base-file", "filename": "/proc/self/fd/3", "read-only": true},
		{"driver": "qcow2", "node-name": "base", "file": "base-file", "read-only": true, "backing": nil},
		{"driver": "file", "node-name": "overlay-file", "filename": filepath.Join(dir, "overlay.qcow2")},
		{"driver": "qcow2", "node-name": "overlay", "file": "overlay-file", "backing": "base"},
		{"driver": "file", "node-name": "seed-file", "filename": filepath.Join(dir, "seed.img"), "read-only": true},
		{"driver": "raw", "node-name": "seed", "file": "seed-file", "read-only": true},
	}
	nodeIDs := make([]string, 1, 1+h.ExtraDisks)
	nodeIDs[0] = "overlay"
	for i := range h.ExtraDisks {
		id := fmt.Sprintf("extra-%d", i)
		nodeIDs = append(nodeIDs, id)
		blocks = append(blocks,
			map[string]any{"driver": "file", "node-name": id + "-file", "filename": filepath.Join(dir, id+".qcow2")},
			map[string]any{"driver": "qcow2", "node-name": id, "file": id + "-file", "backing": nil})
	}
	for _, block := range blocks {
		encoded, err := json.Marshal(block)
		if err != nil {
			return nil, fmt.Errorf("encode QEMU block device: %w", err)
		}
		args = append(args, "-blockdev", string(encoded))
	}
	args = append(args, vmStorageArguments(h, nodeIDs, 0)...)
	if h.recoveryTarget {
		args = append(args, "-device", "virtio-scsi-pci,id=recovery-scsi")
	}
	// The NoCloud seed is a separate read-only virtio device, not a data disk.
	network := "user,id=net0,hostfwd=tcp:127.0.0.1:" + port + "-:22"
	if !h.AllowNetwork {
		network += ",restrict=on"
	}
	args = append(args, "-device", "virtio-blk-pci,drive=seed", "-device", "virtio-rng-pci", "-netdev", network, "-device", "virtio-net-pci,netdev=net0,id=nic0")
	if h.dataLink != nil {
		// JSON keeps socket paths out of QEMU's comma-delimited option syntax.
		netdev, err := json.Marshal(map[string]any{"type": "dgram", "id": "net1", "local": map[string]string{"type": "unix", "path": h.dataLink.Local}, "remote": map[string]string{"type": "unix", "path": h.dataLink.Remote}})
		if err != nil {
			return nil, fmt.Errorf("encode QEMU data link: %w", err)
		}
		args = append(args, "-netdev", string(netdev), "-device", "virtio-net-pci,netdev=net1,id=nic1,mac="+h.dataLink.MAC)
	}
	if h.TPM {
		device := "tpm-tis"
		if h.Architecture == "aarch64" {
			device = "tpm-tis-device"
		}
		args = append(args, "-chardev", "socket,id=tpm,path=tpm.sock", "-tpmdev", "emulator,id=tpm0,chardev=tpm", "-device", device+",tpmdev=tpm0")
	}
	if h.Desktop {
		args = append(args, "-device", "virtio-gpu-pci", "-vnc", "unix:display.sock")
	}
	return args, nil
}

// vmStorageArguments attaches already-defined private block nodes in root-first
// order. Callers supply resolved hardware and at most five nodes. The root boot
// index may leave an earlier slot for installer media; identities stay unchanged
// across the cloud and encrypted lanes.
func vmStorageArguments(h VMHardwareOptions, nodeIDs []string, bootIndex int) []string {
	args := make([]string, 0, 2+4*len(nodeIDs))
	switch h.StorageBus {
	case "virtio-scsi":
		args = append(args, "-device", "virtio-scsi-pci,id=storage")
	case "sata":
		args = append(args, "-device", "ich9-ahci,id=storage")
	}
	for i, id := range nodeIDs {
		var device string
		switch h.StorageBus {
		case "virtio-blk":
			device = "virtio-blk-pci,drive=" + id
		case "virtio-scsi":
			device = "scsi-hd,bus=storage.0,drive=" + id
		case "nvme":
			// Serial belongs to the controller; identity and backend belong to
			// its explicit namespace. A zero UUID lets Linux report the EUI64
			// rather than a randomly generated namespace UUID.
			args = append(args, "-device", fmt.Sprintf("nvme,id=nvme%d,serial=lindm-lab-%d", i, i))
			device = fmt.Sprintf("nvme-ns,bus=nvme%d,nsid=1,drive=%s,eui64=0x%016x,uuid=00000000-0000-0000-0000-000000000000", i, id, uint64(0x0200000000000000)+uint64(i)+1)
		case "sata":
			device = fmt.Sprintf("ide-hd,bus=storage.%d,drive=%s", i, id)
		}
		// Stable identities distinguish writable fixture disks from NoCloud.
		// These are emulated identifiers, not claims about physical hardware.
		if h.StorageBus != "nvme" {
			device += fmt.Sprintf(",serial=lindm-lab-%d", i)
		}
		if h.StorageBus == "virtio-scsi" || h.StorageBus == "sata" {
			device += fmt.Sprintf(",wwn=0x%016x", uint64(0x5000000000000000)+uint64(i)+1)
		}
		if i == 0 {
			device += fmt.Sprintf(",bootindex=%d", bootIndex)
		}
		args = append(args, "-device", device)
	}
	return args
}

type vmRuntimeEvidence struct {
	Architecture      string                     `json:"architecture"`
	Accelerator       string                     `json:"accelerator"`
	QEMUVersion       string                     `json:"qemu_version"`
	FirmwareMode      string                     `json:"firmware_mode"`
	FirmwareVendor    string                     `json:"firmware_vendor,omitempty"`
	FirmwareVersion   string                     `json:"firmware_version,omitempty"`
	Firmware          *EncryptedFirmwareEvidence `json:"firmware,omitempty"`
	FirmwareSetupMode *bool                      `json:"firmware_setup_mode,omitempty"`
	TPM               string                     `json:"tpm"`
	SwtpmVersion      string                     `json:"swtpm_version,omitempty"`
	StorageBus        string                     `json:"storage_bus"`
	StorageController string                     `json:"storage_controller"`
	DiskCount         int                        `json:"disk_count"`
	SeedDisk          bool                       `json:"seed_disk"`
	Desktop           bool                       `json:"desktop"`
	Display           string                     `json:"display"`
	NetworkAccess     string                     `json:"network_access"`
	ClockPolicy       string                     `json:"clock_policy,omitempty"`
	DataLink          string                     `json:"data_link,omitempty"`
	Emulated          bool                       `json:"emulated"`
	Physical          bool                       `json:"physical"`
}

func (v *guestVM) runtimeEvidence(ctx context.Context) (*vmRuntimeEvidence, error) {
	if err := v.processError(); err != nil {
		return nil, err
	}
	version, err := hostCommand(ctx, v.dir, fmt.Sprintf("/proc/%d/exe", v.cmd.Process.Pid), nil, "--version")
	if err != nil {
		return nil, err
	}
	qemu, _, _ := strings.Cut(string(version), "\n")
	if strings.TrimSpace(qemu) == "" {
		return nil, errors.New("incomplete hypervisor evidence")
	}
	h := v.hardware
	e := &vmRuntimeEvidence{Architecture: h.Architecture, Accelerator: h.Accelerator, QEMUVersion: qemu, FirmwareMode: "bios", TPM: "absent", StorageBus: h.StorageBus, DiskCount: 1 + h.ExtraDisks, SeedDisk: true, Desktop: h.Desktop, Display: "none", Emulated: true, Physical: false}
	e.NetworkAccess = "restricted-user"
	if h.AllowNetwork {
		e.NetworkAccess = "user-egress"
	}
	if v.usingOfflineRTC {
		state, err := v.runResult(ctx, "systemctl is-enabled -- "+nativeQuote(h.offlineRTCWaitUnit), nil, 1024, 10*time.Second)
		if err != nil {
			return nil, fmt.Errorf("observe offline RTC bootstrap policy: %w", err)
		}
		if state.ExitCode != 1 || strings.TrimSpace(string(state.Stdout)) != "disabled" || len(state.Stderr) != 0 {
			return nil, errors.New("offline RTC bootstrap did not disable its declared network time wait")
		}
		e.ClockPolicy = "offline-host-utc-rtc; NTP synchronization not asserted"
	}
	if h.dataLink != nil {
		e.DataLink = "nic1 " + h.dataLink.MAC + " host-local unix-dgram L2 peer link"
	}
	switch h.StorageBus {
	case "virtio-blk":
		e.StorageController = "virtio-blk-pci"
	case "virtio-scsi":
		e.StorageController = "virtio-scsi-pci"
	case "nvme":
		e.StorageController = "nvme"
	case "sata":
		e.StorageController = "ich9-ahci"
	}
	if v.firmware != nil {
		e.FirmwareMode = "uefi"
		firmware := *v.firmware
		firmware.CodePath, firmware.VarsPath = "firmware-code.fd", "nvram.fd"
		e.Firmware = &firmware
	}
	if h.TPM {
		e.TPM = "swtpm-2.0-emulated"
		if v.tpm == nil {
			return nil, errors.New("selected TPM has no owned emulator process")
		}
		version, err := hostCommand(ctx, v.dir, fmt.Sprintf("/proc/%d/exe", v.tpm.cmd.Process.Pid), nil, "--version")
		if err != nil {
			return nil, err
		}
		e.SwtpmVersion, _, _ = strings.Cut(string(version), "\n")
		if strings.TrimSpace(e.SwtpmVersion) == "" {
			return nil, errors.New("missing TPM emulator version evidence")
		}
	}
	if h.Desktop {
		e.Display = "virtio-gpu-pci/unix-vnc"
	}
	// AArch64 firmware need not expose DMI. Do not label missing SMBIOS as
	// SeaBIOS/OVMF or reuse x86 evidence on a different architecture.
	firmware, err := v.run(ctx, "for f in /sys/class/dmi/id/bios_vendor /sys/class/dmi/id/bios_version; do if test -r \"$f\"; then cat \"$f\" || exit; else printf '\\n'; fi; done", nil, 4096, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("read guest firmware evidence: %w", err)
	}
	fields := strings.Split(strings.TrimSuffix(string(firmware), "\n"), "\n")
	if len(fields) != 2 || (h.Architecture == "x86_64" && (strings.TrimSpace(fields[0]) == "" || strings.TrimSpace(fields[1]) == "")) {
		return nil, errors.New("incomplete guest firmware evidence")
	}
	e.FirmwareVendor, e.FirmwareVersion = fields[0], fields[1]
	nativeFirmware, err := (vmInventoryOracle{ctx: ctx, vm: v}).firmware()
	if err != nil {
		return nil, fmt.Errorf("observe runtime firmware: %w", err)
	}
	if err := compareVMFirmware(&h, nativeFirmware); err != nil {
		return nil, err
	}
	e.FirmwareSetupMode, err = inspectFirmwareSetupMode(ctx, v, &h)
	if err != nil {
		return nil, err
	}
	e.FirmwareMode = nativeFirmware.GetMode().GetValue()
	if e.Firmware != nil {
		e.Firmware.SecureBoot = nativeFirmware.GetSecureBoot().GetValue() == "enabled"
	}
	return e, nil
}

// Firmware configuration is not evidence that the guest actually booted with
// those settings. Both on and off requests require successful native observation.
func compareVMFirmware(hardware *VMHardwareOptions, firmware *inventoryv1.FirmwareDetails) error {
	mode, secureBoot := "bios", ""
	if hardware.Firmware != nil {
		mode, secureBoot = "uefi", "disabled"
		if hardware.Firmware.SecureBoot {
			secureBoot = "enabled"
		}
	}
	if firmware.GetMode().GetStatus() != truthSuccess || firmware.GetMode().GetValue() != mode {
		return errors.New("observed firmware differs from selected emulation")
	}
	if secureBoot != "" && (firmware.GetSecureBoot().GetStatus() != truthSuccess || firmware.GetSecureBoot().GetValue() != secureBoot) {
		value := firmware.GetSecureBoot().GetValue()
		if value != "" && value != "enabled" && value != "disabled" {
			value = "unexpected (withheld)"
		}
		return fmt.Errorf("observed Secure Boot differs from selected emulation: expected %q, observed status %s value %q", secureBoot, firmware.GetSecureBoot().GetStatus(), value)
	}
	return nil
}

// setNetworkLink changes only this owned guest's NIC. QMP remains reachable when
// SSH is disconnected, so callers can restore the link without host networking.
// Calls are sequential, like the guest SSH lifecycle.
func (v *guestVM) setNetworkLink(ctx context.Context, up bool) error {
	return v.qmpCommand(ctx, map[string]any{"execute": "set_link", "arguments": map[string]any{"name": "nic0", "up": up}, "id": "link"})
}

func (v *guestVM) finishStartup(ctx context.Context) error {
	if v.stopRebootAfterConnect {
		if err := v.qmpCommand(ctx, map[string]any{"execute": "set-action", "arguments": map[string]any{"reboot": "shutdown"}, "id": "reboot"}); err != nil {
			return fmt.Errorf("enforce guest reboot policy: %w", err)
		}
		v.stopRebootAfterConnect = false
	}
	return v.processError()
}

func (v *guestVM) qmpCommand(ctx context.Context, command map[string]any) (err error) {
	if err := v.processError(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(v.dir, "qmp.sock"))
	if err != nil {
		return fmt.Errorf("connect guest QMP: %w", err)
	}
	defer func() { err = errors.Join(err, conn.Close()) }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	return executeQMPCommand(conn, command)
}

func executeQMPCommand(conn io.ReadWriter, request map[string]any) error {
	decoder := json.NewDecoder(io.LimitReader(conn, 64<<10))
	var greeting map[string]json.RawMessage
	if err := decoder.Decode(&greeting); err != nil {
		return fmt.Errorf("read QMP greeting: %w", err)
	}
	if _, ok := greeting["QMP"]; !ok {
		return errors.New("missing QMP greeting")
	}
	encoder := json.NewEncoder(conn)
	for _, command := range []map[string]any{
		{"execute": "qmp_capabilities", "id": "capabilities"},
		request,
	} {
		if err := encoder.Encode(command); err != nil {
			return fmt.Errorf("write QMP command: %w", err)
		}
		for {
			var response struct {
				ID     string          `json:"id"`
				Event  string          `json:"event"`
				Error  json.RawMessage `json:"error"`
				Return json.RawMessage `json:"return"`
			}
			if err := decoder.Decode(&response); err != nil {
				return fmt.Errorf("read QMP response: %w", err)
			}
			if response.Event != "" {
				continue
			}
			if response.ID != command["id"] || len(response.Error) != 0 || len(response.Return) == 0 {
				return fmt.Errorf("QMP rejected %s command", request["execute"])
			}
			break
		}
	}
	return nil
}

func defaultVMHardware(options *VMHardwareOptions) (VMHardwareOptions, error) {
	return resolveVMHardware(options, runtime.GOARCH)
}
