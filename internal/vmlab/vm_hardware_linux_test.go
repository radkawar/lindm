//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestVMHardwareTPMExitPreservesQEMUDiagnostics(t *testing.T) {
	tpm := &encryptedProcess{done: make(chan struct{}), log: new(vmLog)}
	close(tpm.done)
	vm := &guestVM{dir: t.TempDir(), tpm: tpm, done: make(chan struct{}), log: new(vmLog)}
	if _, err := vm.log.Write([]byte("QEMU device initialization failed")); err != nil {
		t.Fatal(err)
	}
	err := vm.processError()
	if err == nil || !strings.Contains(err.Error(), "QEMU device initialization failed") {
		t.Fatalf("TPM disconnect hid QEMU startup diagnostics: %v", err)
	}
}

func TestVMHardwareAllowsFirmwareStartupReset(t *testing.T) {
	for _, firmware := range []*EncryptedFirmwareOptions{nil, {SecureBoot: true}} {
		for _, allowReboot := range []bool{false, true} {
			h := VMHardwareOptions{Architecture: "x86_64", Accelerator: "kvm", StorageBus: "nvme", TPM: true, Firmware: firmware}
			args, err := configuredVMArguments(h, t.TempDir(), "12345", allowReboot)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := slices.Contains(args, "-no-reboot"), !allowReboot && firmware == nil; got != want {
				t.Fatalf("firmware=%v allowReboot=%v: no-reboot=%v, want %v", firmware != nil, allowReboot, got, want)
			}
		}
	}
}

// A firmware reset is allowed only during readiness, not for the remainder of
// a caller's no-reboot run. A rejected monitor command must fail readiness.
func TestVMHardwareStartupRebootPolicyRequiresAcknowledgement(t *testing.T) {
	for _, test := range []struct {
		name  string
		reply string
		ok    bool
	}{
		{"acknowledged", "{\"id\":\"reboot\",\"return\":{}}\n", true},
		{"rejected", "{\"id\":\"reboot\",\"error\":{\"class\":\"CommandNotFound\"}}\n", false},
		{"unrelated", "{\"id\":\"other\",\"return\":{}}\n", false},
		{"truncated", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			listener, err := net.Listen("unix", filepath.Join(dir, "qmp.sock"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			result := make(chan error, 1)
			go func() {
				result <- func() error {
					conn, err := listener.Accept()
					if err != nil {
						return err
					}
					defer func() { _ = conn.Close() }()
					if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
						return err
					}
					if _, err := io.WriteString(conn, "{\"QMP\":{}}\n"); err != nil {
						return err
					}
					decoder := json.NewDecoder(conn)
					var capabilities struct {
						Execute string `json:"execute"`
					}
					if err := decoder.Decode(&capabilities); err != nil {
						return err
					}
					if capabilities.Execute != "qmp_capabilities" {
						return errors.New("missing QMP capability negotiation")
					}
					if _, err := io.WriteString(conn, "{\"id\":\"capabilities\",\"return\":{}}\n"); err != nil {
						return err
					}
					var command struct {
						Execute   string            `json:"execute"`
						Arguments map[string]string `json:"arguments"`
					}
					if err := decoder.Decode(&command); err != nil {
						return err
					}
					if command.Execute != "set-action" || len(command.Arguments) != 1 || command.Arguments["reboot"] != "shutdown" {
						return errors.New("startup did not restore shutdown-on-reboot policy")
					}
					_, err = io.WriteString(conn, test.reply)
					return err
				}()
			}()
			vm := &guestVM{dir: dir, done: make(chan struct{}), log: new(vmLog), stopRebootAfterConnect: true}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err = vm.finishStartup(ctx)
			if (err == nil) != test.ok || vm.stopRebootAfterConnect == test.ok {
				t.Fatalf("readiness error=%v pending policy=%v, want success=%v", err, vm.stopRebootAfterConnect, test.ok)
			}
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("QMP peer did not finish")
			}
			if test.ok {
				if err := listener.Close(); err != nil {
					t.Fatal(err)
				}
				if err := vm.finishStartup(ctx); err != nil {
					t.Fatalf("readiness repeated an already acknowledged transition: %v", err)
				}
			}
		})
	}
}

func TestVMHardwareStartupPreservesExistingRebootPolicy(t *testing.T) {
	// Manually assembled encrypted guests and allowReboot callers have no
	// pending policy transition and need no QMP connection at SSH readiness.
	vm := &guestVM{dir: t.TempDir(), done: make(chan struct{}), log: new(vmLog)}
	if err := vm.finishStartup(context.Background()); err != nil {
		t.Fatalf("unchanged reboot policy required a QMP connection: %v", err)
	}
}

func TestVMHardwareArchitectureAndAcceleration(t *testing.T) {
	firmware := &EncryptedFirmwareOptions{Code: "/firmware/code", Vars: "/firmware/vars", Package: "firmware", Version: "1"}
	for _, test := range []struct {
		name    string
		host    string
		options *VMHardwareOptions
		arch    string
		accel   string
	}{
		{"existing x86 defaults", "amd64", nil, "x86_64", "kvm"},
		{"explicit x86 emulation", "amd64", &VMHardwareOptions{Accelerator: "tcg"}, "x86_64", "tcg"},
		{"foreign arm defaults", "amd64", &VMHardwareOptions{Architecture: "aarch64", Firmware: firmware}, "aarch64", "tcg"},
		{"native arm", "arm64", &VMHardwareOptions{Architecture: "aarch64", Firmware: firmware}, "aarch64", "kvm"},
		{"foreign x86 defaults", "arm64", nil, "x86_64", "tcg"},
	} {
		t.Run(test.name, func(t *testing.T) {
			h, err := resolveVMHardware(test.options, test.host)
			if err != nil {
				t.Fatal(err)
			}
			if h.Architecture != test.arch || h.Accelerator != test.accel || h.StorageBus != "virtio-blk" || h.TPM || h.ExtraDisks != 0 || h.Desktop {
				t.Fatalf("unexpected resolved hardware: %#v", h)
			}
			if h.Accelerator == "tcg" {
				if err := checkVMAcceleration(h); err != nil {
					t.Fatalf("software emulation must not require /dev/kvm: %v", err)
				}
			}
		})
	}
}

func TestVMHardwareRejectsUnsupportedAndUnboundedRequests(t *testing.T) {
	for _, options := range []VMHardwareOptions{
		{Architecture: "riscv64"},
		{Accelerator: "auto"},
		{StorageBus: "host"},
		{ExtraDisks: -1},
		{ExtraDisks: 5},
		{Architecture: "aarch64"},
		{Architecture: "aarch64", Accelerator: "kvm"},
		{Firmware: &EncryptedFirmwareOptions{Code: "/firmware/code"}},
	} {
		if _, err := resolveVMHardware(&options, "amd64"); err == nil {
			t.Fatalf("accepted unsupported hardware: %#v", options)
		}
	}
	for _, bus := range []string{"virtio-blk", "virtio-scsi", "nvme", "sata"} {
		if _, err := resolveVMHardware(&VMHardwareOptions{StorageBus: bus, ExtraDisks: 4}, "amd64"); err != nil {
			t.Fatalf("rejected bounded %s disks: %v", bus, err)
		}
	}
}

// The peer link must stay a private two-endpoint segment: a path that escapes
// the lane's directory, a broadcast/global MAC, or a comma-carrying option
// would join or address another lane's guests.
func TestVMHardwareDataLink(t *testing.T) {
	link := &vmDataLink{MAC: "52:54:00:77:00:10", Local: "/private/link,dir/device.sock", Remote: "/private/link,dir/peer.sock"}
	if _, err := resolveVMHardware(&VMHardwareOptions{dataLink: link}, "amd64"); err == nil {
		t.Fatal("accepted comma-carrying data link paths")
	}
	for _, bad := range []vmDataLink{
		{MAC: "52:54:00:77:00:1G", Local: "/l/a.sock", Remote: "/l/b.sock"},
		{MAC: "52:54:00:77:00:1A", Local: "/l/a.sock", Remote: "/l/b.sock"},
		{MAC: "53:54:00:77:00:10", Local: "/l/a.sock", Remote: "/l/b.sock"},
		{MAC: "00:16:3e:77:00:10", Local: "/l/a.sock", Remote: "/l/b.sock"},
		{MAC: "52:54:00:77:00:10", Local: "l/a.sock", Remote: "/l/b.sock"},
		{MAC: "52:54:00:77:00:10", Local: "/l/a.sock", Remote: "/other/b.sock"},
		{MAC: "52:54:00:77:00:10", Local: "/l/a.sock", Remote: "/l/a.sock"},
		{MAC: "52:54:00:77:00:10", Local: "/l/../a.sock", Remote: "/l/b.sock"},
		{MAC: "52:54:00:77:00:10", Local: "/" + strings.Repeat("l", 100) + "/a.sock", Remote: "/" + strings.Repeat("l", 100) + "/b.sock"},
	} {
		if _, err := resolveVMHardware(&VMHardwareOptions{dataLink: &bad}, "amd64"); err == nil {
			t.Fatalf("accepted unsafe data link %#v", bad)
		}
	}
	link = &vmDataLink{MAC: "52:54:00:77:00:10", Local: "/private/link/device.sock", Remote: "/private/link/peer.sock"}
	h, err := resolveVMHardware(&VMHardwareOptions{dataLink: link}, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	link.Remote = "/private/link/other.sock"
	args, err := configuredVMArguments(h, "/private/run", "12345", false)
	if err != nil {
		t.Fatal(err)
	}
	var netdevs []map[string]any
	devices := 0
	for i, arg := range args {
		if i+1 == len(args) {
			break
		}
		if arg == "-netdev" && strings.HasPrefix(args[i+1], "{") {
			var netdev map[string]any
			if err := json.Unmarshal([]byte(args[i+1]), &netdev); err != nil {
				t.Fatal(err)
			}
			netdevs = append(netdevs, netdev)
		}
		if arg == "-device" && args[i+1] == "virtio-net-pci,netdev=net1,id=nic1,mac=52:54:00:77:00:10" {
			devices++
		}
	}
	want := map[string]any{"type": "dgram", "id": "net1", "local": map[string]any{"type": "unix", "path": "/private/link/device.sock"}, "remote": map[string]any{"type": "unix", "path": "/private/link/peer.sock"}}
	if len(netdevs) != 1 || devices != 1 || !jsonEqual(netdevs[0], want) {
		t.Fatalf("unexpected data link arguments: %q", args)
	}
	plain, err := configuredVMArguments(VMHardwareOptions{Architecture: "x86_64", Accelerator: "kvm", StorageBus: "virtio-blk"}, "/private/run", "12345", false)
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(plain, func(arg string) bool { return strings.Contains(arg, "net1") }) {
		t.Fatal("ordinary guest gained a data link")
	}
}

func jsonEqual(a, b any) bool {
	left, errA := json.Marshal(a)
	right, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(left, right)
}

// Encryption fixtures select the disposable disk by serial, not a guessed
// /dev name. A collision with root or the seed could destroy the wrong disk.
func TestVMHardwareFixtureDiskIdentity(t *testing.T) {
	for _, bus := range []string{"virtio-blk", "virtio-scsi", "nvme", "sata"} {
		t.Run(bus, func(t *testing.T) {
			h, err := resolveVMHardware(&VMHardwareOptions{StorageBus: bus, ExtraDisks: 4}, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			args, err := configuredVMArguments(h, "/private/run,with-comma", "12345", false)
			if err != nil {
				t.Fatal(err)
			}
			identities := make(map[string]string)
			controllers := make(map[string]string)
			worldwide := make(map[string]bool)
			seed := false
			for i, arg := range args {
				if arg != "-device" || i+1 == len(args) {
					continue
				}
				properties := make(map[string]string)
				model, _, _ := strings.Cut(args[i+1], ",")
				for part := range strings.SplitSeq(args[i+1], ",") {
					key, value, _ := strings.Cut(part, "=")
					properties[key] = value
				}
				drive, serial := properties["drive"], properties["serial"]
				if model == "nvme" {
					controllers[properties["id"]] = serial
				}
				if model == "nvme-ns" {
					serial = controllers[properties["bus"]]
				}
				if drive == "seed" {
					seed = true
					if serial != "" {
						t.Fatal("NoCloud seed has a writable fixture identity")
					}
				} else if drive != "" {
					if serial == "" || identities[serial] != "" {
						t.Fatal("missing or duplicate writable disk identity")
					}
					identities[serial] = drive
					wwn := properties["wwn"]
					if bus == "nvme" {
						wwn = properties["eui64"]
						if properties["uuid"] != "00000000-0000-0000-0000-000000000000" {
							t.Fatal("NVMe namespace identity depends on a random UUID")
						}
					}
					if bus == "virtio-blk" {
						if wwn != "" {
							t.Fatal("virtio-blk invents a WWN")
						}
					} else {
						if wwn == "" || wwn == "0x0000000000000000" || worldwide[wwn] {
							t.Fatal("missing, zero or duplicate writable disk WWN")
						}
						worldwide[wwn] = true
					}
				}
			}
			if !seed || len(identities) != 5 || identities["lindm-lab-0"] != "overlay" || identities["lindm-lab-1"] != "extra-0" || identities["lindm-lab-4"] != "extra-3" {
				t.Fatalf("unsafe disposable disk identities: %#v", identities)
			}
		})
	}
}

func TestVMHardwarePinsCallerFirmwareOptions(t *testing.T) {
	options := VMHardwareOptions{Firmware: &EncryptedFirmwareOptions{Code: "/firmware/code", Vars: "/firmware/vars", Package: "firmware", Version: "1", SecureBoot: true}}
	h, err := resolveVMHardware(&options, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	options.Firmware.SecureBoot = false
	options.Firmware.Code = "/changed"
	if !h.Firmware.SecureBoot || h.Firmware.Code != "/firmware/code" || options.Architecture != "" {
		t.Fatal("resolved hardware aliases or mutates caller options")
	}
}

// Protocol transcripts are not VM evidence. These regressions ensure a denied,
// unrelated or truncated monitor reply cannot be reported as a network outage.
func TestQMPNetworkLinkRequiresAcknowledgement(t *testing.T) {
	for _, up := range []bool{false, true} {
		input := strings.NewReader("{\"QMP\":{}}\n{\"event\":\"RESUME\"}\n{\"id\":\"capabilities\",\"return\":{}}\n{\"id\":\"link\",\"return\":{}}\n")
		var output bytes.Buffer
		conn := struct {
			io.Reader
			io.Writer
		}{input, &output}
		if err := executeQMPCommand(conn, map[string]any{"execute": "set_link", "arguments": map[string]any{"name": "nic0", "up": up}, "id": "link"}); err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(&output)
		var capabilities struct {
			Execute string `json:"execute"`
		}
		var link struct {
			Execute   string `json:"execute"`
			Arguments struct {
				Name string `json:"name"`
				Up   bool   `json:"up"`
			} `json:"arguments"`
		}
		if err := decoder.Decode(&capabilities); err != nil {
			t.Fatal(err)
		}
		if err := decoder.Decode(&link); err != nil {
			t.Fatal(err)
		}
		if capabilities.Execute != "qmp_capabilities" || link.Execute != "set_link" || link.Arguments.Name != "nic0" || link.Arguments.Up != up {
			t.Fatalf("network command targeted wrong state: %#v", link)
		}
	}
	for _, reply := range []string{
		"{\"return\":{}}",
		"{\"QMP\":{}}\n{\"id\":\"capabilities\",\"error\":{\"class\":\"CommandNotFound\"}}",
		"{\"QMP\":{}}\n{\"id\":\"capabilities\",\"return\":{}}\n{\"id\":\"other\",\"return\":{}}",
		"{\"QMP\":{}}\n{\"id\":\"capabilities\",\"return\":{}}\n{\"id\":\"link\",\"error\":{\"class\":\"DeviceNotFound\"}}",
		"{\"QMP\":{}}\n{\"id\":\"capabilities\",\"return\":{}}\n{\"id\":\"link\"}",
		"{\"QMP\":{}}\n{\"id\":\"capabilities\",\"return\":{}}",
		"{\"QMP\":\"" + strings.Repeat("x", 64<<10) + "\"}",
	} {
		conn := struct {
			io.Reader
			io.Writer
		}{strings.NewReader(reply), io.Discard}
		if err := executeQMPCommand(conn, map[string]any{"execute": "set_link", "arguments": map[string]any{"name": "nic0", "up": false}, "id": "link"}); err == nil {
			t.Fatal("accepted missing, unrelated, denied or unbounded QMP acknowledgement")
		}
	}
}

func TestVMCloseReapsTPMBeforeRemovingPrivateState(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "owned")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(parent, "unrelated")
	if err := os.WriteFile(unrelated, []byte("retain"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nvram.fd"), []byte("private-state"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// A real owned helper process exercises teardown; this does not emulate or
	// claim qualification of swtpm, EFI or guest boot.
	process, err := startEncryptedProcess(ctx, dir, "sleep", "60")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := process.stop(); err != nil {
			t.Error(err)
		}
	})
	vm := &guestVM{dir: dir, tpm: process}
	if err := vm.close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-process.done:
	default:
		t.Fatal("private state removed before owned TPM process was reaped")
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned state remains after close: %v", err)
	}
	if data, err := os.ReadFile(unrelated); err != nil || string(data) != "retain" {
		t.Fatalf("cleanup touched unrelated state: %v", err)
	}
}

// AAVMF 2024.02 enumerated no disk on ich9-ahci and fell through to PXE/HTTP
// boot (aarch64-aavmf-sata-boot-diagnosis-01); refuse instead of timing out.
func TestVMHardwareRefusesUnbootableARMSATA(t *testing.T) {
	firmware := &EncryptedFirmwareOptions{Code: "code", Vars: "vars", Package: "qemu-efi-aarch64", Version: "pinned"}
	if _, err := resolveVMHardware(&VMHardwareOptions{Architecture: "aarch64", StorageBus: "sata", Firmware: firmware}, "arm64"); err == nil || !strings.Contains(err.Error(), "AHCI") {
		t.Fatalf("accepted an aarch64 SATA guest AAVMF cannot boot: %v", err)
	}
	for _, bus := range []string{"virtio-blk", "virtio-scsi", "nvme"} {
		if _, err := resolveVMHardware(&VMHardwareOptions{Architecture: "aarch64", StorageBus: bus, Firmware: firmware}, "arm64"); err != nil {
			t.Fatalf("rejected bootable aarch64 %s: %v", bus, err)
		}
	}
}
