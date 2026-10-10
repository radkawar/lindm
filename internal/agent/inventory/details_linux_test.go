//go:build linux

package inventory

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func detailFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestCapturedCPUAndMemory(t *testing.T) {
	cpu := detailFixture(t, "cpuinfo.txt")
	got := parseCPU(cpu, nil)
	if got.Model.Value != "13th Gen Intel(R) Core(TM) i7-13700K" || got.LogicalCores.Value != 1 || got.PhysicalCores.Value != 1 || got.X86_64Level.Value != "x86-64-v3" {
		t.Fatalf("cpu: %v", got)
	}
	// A weaker second CPU must lower the advertised baseline, not select the
	// first stanza or union instruction flags across heterogeneous processors.
	second := strings.Replace(string(cpu), "processor\t: 0", "processor\t: 1", 1)
	second = strings.Replace(second, " avx2 ", " ", 1)
	mixed := parseCPU([]byte(string(cpu)+second), nil)
	if mixed.LogicalCores.Value != 2 || mixed.PhysicalCores.Value != 1 || mixed.X86_64Level.Value != "x86-64-v2" {
		t.Fatalf("mixed CPU: %v", mixed)
	}
	if got := parseCPU(append(cpu, cpu...), nil); got.LogicalCores.Status != invalid {
		t.Fatalf("duplicate processors: %v", got)
	}
	if got := parseCPU(nil, fs.ErrPermission); got.Model.Status != inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED {
		t.Fatalf("denied CPU: %v", got)
	}
	memory := parseMemory(detailFixture(t, "meminfo.txt"), nil)
	if memory.TotalBytes.Value != 65396600*1024 || memory.AvailableBytes.Value != 54929412*1024 || memory.SwapTotalBytes.Value != 42205172*1024 {
		t.Fatalf("memory: %v", memory)
	}
	bad := parseMemory([]byte("MemTotal: 2 MB\nMemAvailable: 5 kB\nSwapTotal: 0 kB\n"), nil)
	if bad.TotalBytes.Status != invalid || bad.SwapTotalBytes.Status != success || bad.SwapTotalBytes.Value != 0 {
		t.Fatalf("units/zero: %v", bad)
	}
	if got := parseMemory([]byte("MemTotal: 18446744073709551615 kB\n"), nil); got.TotalBytes.Status != invalid || got.AvailableBytes.Status != unavailable {
		t.Fatalf("overflow/missing: %v", got)
	}
}

func TestLocalUsersModulesAndBootParsing(t *testing.T) {
	users := parseLocalUsers([]byte("root:x:0:0:secret gecos:/root:/bin/bash\nservice:!:999:999:hidden:/srv:/usr/sbin/nologin\n"), nil)
	if users.Status != success || len(users.Users) != 2 || users.Users[1].Uid != 999 {
		t.Fatalf("users: %v", users)
	}
	data, err := protojson.Marshal(users)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret") || strings.Contains(string(data), "hidden") || strings.Contains(string(data), "/root") {
		t.Fatalf("private passwd fields retained: %s", data)
	}
	for _, data := range []string{"bad\n", "root:x:4294967296:0::/:/bin/sh\n", "root:x:0:0::/:/bin/sh"} {
		if got := parseLocalUsers([]byte(data), nil); got.Status != invalid || len(got.Users) != 0 {
			t.Fatalf("malformed passwd accepted: %v", got)
		}
	}
	if got := parseLocalUsers(nil, fs.ErrNotExist); got.Status != unavailable {
		t.Fatalf("missing passwd: %v", got)
	}
	if got := parseModuleCount(detailFixture(t, "modules.txt"), nil); got.Status != success || got.Value != 3 {
		t.Fatalf("modules: %v", got)
	}
	if got := parseModuleCount(nil, nil); got.Status != success || got.Value != 0 {
		t.Fatalf("empty module list: %v", got)
	}
	if got := parseModuleCount([]byte("broken\n"), nil); got.Status != invalid {
		t.Fatalf("module parse failure: %v", got)
	}
	if got := parseUptime([]byte("123.45 456.78\n"), nil); got.Value != 123 || got.Status != success {
		t.Fatalf("uptime: %v", got)
	}
	for _, data := range []string{"NaN 0.00", "-1.00 0.00", "123.45 junk", "123.45"} {
		if got := parseUptime([]byte(data), nil); got.Status != invalid {
			t.Fatalf("bad uptime: %v", got)
		}
	}
	if got := parseBootTime([]byte("cpu 1 2 3\nbtime 1770000000\n"), nil); got.Value != 1770000000 {
		t.Fatalf("boot: %v", got)
	}
	if got := parseBootTime([]byte("btime 1\nbtime 2\n"), nil); got.Status != invalid {
		t.Fatalf("duplicate boot: %v", got)
	}
}

func TestStorageEncryptionAndNetworkBoundaries(t *testing.T) {
	storage := parseStorage(strings.NewReader(`{"blockdevices":[{"name":"sda","type":"disk","size":1000,"fstype":null,"mountpoint":null,"pkname":null},{"name":"sda1","type":"part","size":900,"fstype":"crypto_LUKS","pkname":"sda"},{"name":"crypt","type":"crypt","size":800,"fstype":"ext4","mountpoint":"/","pkname":"sda1"},{"name":"lv","type":"lvm","size":700,"fstype":"xfs","pkname":"crypt"}]}`))
	if storage.Status != success || len(storage.Devices) != 4 {
		t.Fatalf("storage: %v", storage)
	}
	for i, want := range []string{"none", "luks", "dm-crypt", "inherited-dm-crypt"} {
		if storage.Devices[i].Encryption.Value != want {
			t.Fatalf("encryption %d: %v", i, storage.Devices[i])
		}
	}
	if storage.Devices[0].Encryption.Status != success {
		t.Fatal("explicit null signature must remain distinct from an omitted source field")
	}
	for _, data := range []string{`{}`, `{"blockdevices":null}`, `{"blockdevices":[{"name":"sda","type":"disk","size":-1}]}`, `{"blockdevices":[]} {}`} {
		if got := parseStorage(strings.NewReader(data)); got.Status != invalid || len(got.Devices) != 0 {
			t.Fatalf("invalid storage: %v", got)
		}
	}
	network := parseNetwork(strings.NewReader(`[{"ifname":"eth0","address":"02:00:00:00:00:01","operstate":"UP","addr_info":[{"family":"inet","local":"192.0.2.1","prefixlen":24},{"family":"inet6","local":"2001:db8::1","prefixlen":64}]}]`))
	if network.Status != success || len(network.Interfaces) != 1 || len(network.Interfaces[0].Addresses.Values) != 2 {
		t.Fatalf("network: %v", network)
	}
	bad := parseNetwork(strings.NewReader(`[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.0.2.1","prefixlen":99}]}]`))
	if bad.Interfaces[0].Addresses.Status != invalid || len(bad.Interfaces[0].Addresses.Values) != 0 {
		t.Fatalf("bad prefix: %v", bad)
	}
	if got := parseNetwork(strings.NewReader(`[{"ifname":"lo","addr_info":[]}]`)); got.Interfaces[0].Addresses.Status != success {
		t.Fatalf("actual empty addresses: %v", got)
	}
	if got := parseNetwork(strings.NewReader(`[{"ifname":"lo"}]`)); got.Interfaces[0].Addresses.Status != unavailable {
		t.Fatalf("missing addresses: %v", got)
	}
}

func TestApplicationsAndSessionCounts(t *testing.T) {
	flatpak := parseFlatpak(strings.NewReader("org.example.App\t1.2\tx86_64\n"))
	if flatpak.Status != success || len(flatpak.Applications) != 1 || flatpak.Applications[0].Scope.Value != "system" {
		t.Fatalf("flatpak: %v", flatpak)
	}
	if got := parseFlatpak(strings.NewReader(strings.Repeat("a\t1\tx86_64\n", 2049))); got.Status != capacity || len(got.Applications) != 0 {
		t.Fatalf("app limit: %v", got)
	}
	rows, status := parseSessionRows(strings.NewReader(`{"type":"a(uso)","data":[[[1000,"private-user","/org/freedesktop/login1/user/_1000"]]]}`), "a(uso)")
	if status != success || len(rows) != 1 {
		t.Fatalf("session count: %d %v", len(rows), status)
	}
	rows, status = parseSessionRows(strings.NewReader(`{"type":"a(susso)","data":[[]]}`), "a(susso)")
	if status != success || len(rows) != 0 {
		t.Fatalf("real empty sessions: %d %v", len(rows), status)
	}
	_, status = parseSessionRows(strings.NewReader(`{"type":"a(uso)","data":[[["bad","user","/path"]]]}`), "a(uso)")
	if status != invalid {
		t.Fatalf("malformed D-Bus UID: %v", status)
	}
}

func fixtureDetails(root string) detailSources {
	path := func(name string) string { return filepath.Join(root, strings.TrimPrefix(name, "/")) }
	return detailSources{
		readFile: func(name string) ([]byte, error) { return readDetailFile(path(name)) },
		readDir:  func(name string) ([]fs.DirEntry, error) { return readDetailDir(path(name)) },
		stat:     func(name string) (fs.FileInfo, error) { return os.Stat(path(name)) },
		run: func(context.Context, backend, func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
			return unavailable
		},
		snap: func(context.Context) *inventoryv1.ApplicationDetails {
			return &inventoryv1.ApplicationDetails{Status: unavailable}
		},
		sessions: func(context.Context) *inventoryv1.SessionCounts {
			return &inventoryv1.SessionCounts{Users: number(0, fs.ErrNotExist), Sessions: number(0, fs.ErrNotExist)}
		},
	}
}

func TestSysfsAndFailureStatuses(t *testing.T) {
	sources := fixtureDetails("testdata")
	power := collectPower(context.Background(), sources)
	if power.Chassis.Value != "35" || power.Batteries.Status != success || len(power.Batteries.Items) != 0 {
		t.Fatalf("captured power: %v", power)
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sys/firmware/efi/efivars"), 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
	for _, test := range []struct {
		data   []byte
		want   string
		status inventoryv1.CollectionStatus
	}{{[]byte{6, 0, 0, 0, 1}, "enabled", success}, {[]byte{6, 0, 0, 0, 0}, "disabled", success}, {[]byte{1}, "", invalid}, {[]byte{6, 0, 0, 0, 2}, "", invalid}} {
		if err := os.WriteFile(path, test.data, 0600); err != nil {
			t.Fatal(err)
		}
		got := collectFirmware(context.Background(), fixtureDetails(root))
		if got.Mode.Value != "uefi" || got.SecureBoot.Value != test.want || got.SecureBoot.Status != test.status {
			t.Fatalf("EFI: %v", got)
		}
	}
	denied := fixtureDetails(root)
	denied.readFile = func(string) ([]byte, error) { return nil, fs.ErrPermission }
	if got := collectFirmware(context.Background(), denied); got.SecureBoot.Status != inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED {
		t.Fatalf("denied EFI: %v", got)
	}
	if err := os.MkdirAll(filepath.Join(root, "sys/class/tpm"), 0700); err != nil {
		t.Fatal(err)
	}
	if got := collectTPM(context.Background(), fixtureDetails(root)); got.Present.Status != success || got.Present.Value || got.Version.Status != unavailable {
		t.Fatalf("absent TPM: %v", got)
	}
	if err := os.MkdirAll(filepath.Join(root, "sys/class/tpm/tpm0"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sys/class/tpm/tpm0/tpm_version_major"), []byte("2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := collectTPM(context.Background(), fixtureDetails(root)); !got.Present.Value || got.Version.Value != "2" {
		t.Fatalf("TPM: %v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	details := collectDetails(ctx, fixtureDetails(root))
	if err := protovalidate.Validate(details); err != nil {
		t.Fatal(err)
	}
	if details.Cpu.Model.Status != inventoryv1.CollectionStatus_COLLECTION_STATUS_TIMEOUT || details.Memory.TotalBytes.Status != inventoryv1.CollectionStatus_COLLECTION_STATUS_TIMEOUT {
		t.Fatalf("canceled details: %v", details)
	}
}

func TestDetailPayloadBudget(t *testing.T) {
	got := collectDetails(context.Background(), fixtureDetails(t.TempDir()))
	got.Flatpak = &inventoryv1.ApplicationDetails{Status: success}
	for range 2048 {
		got.Flatpak.Applications = append(got.Flatpak.Applications, &inventoryv1.Application{Name: strings.Repeat("a", 512), Version: observed("1", nil), Architecture: observed("x86_64", nil), Scope: observed("system", nil)})
	}
	boundDetails(got)
	if got.Flatpak.Status != capacity || len(got.Flatpak.Applications) != 0 {
		t.Fatal("oversized applications were partially published")
	}
	if err := protovalidate.Validate(got); err != nil {
		t.Fatal(err)
	}
	data, err := (protojson.MarshalOptions{Multiline: true}).Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > 512<<10 || proto.Size(got) > 512<<10 {
		t.Fatal("details exceed host envelope")
	}
}

func TestBackendPresenceAndFileBounds(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "usr/bin"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr/bin/dpkg-query"), []byte("fixture executable marker\n"), 0700); err != nil {
		t.Fatal(err)
	}
	got := collectBackends(context.Background(), fixtureDetails(root))
	if got.Dpkg.Status != success || !got.Dpkg.Value || got.Rpm.Status != success || got.Rpm.Value {
		t.Fatalf("backend presence: %v", got)
	}
	sources := fixtureDetails(root)
	sources.stat = func(string) (fs.FileInfo, error) { return nil, fs.ErrPermission }
	if got := collectBackends(context.Background(), sources); got.Dpkg.Status != inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED {
		t.Fatalf("denied backend: %v", got)
	}
	large := filepath.Join(root, "large")
	if err := os.WriteFile(large, []byte(strings.Repeat("x", maxDetailFile+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readDetailFile(large); !errors.Is(err, errCapacity) {
		t.Fatalf("unbounded detail file: %v", err)
	}
	if _, err := readDetailFile(root); !errors.Is(err, errInvalid) {
		t.Fatalf("directory accepted as file: %v", err)
	}
	if status := decodeNative(strings.NewReader(strings.Repeat(" ", maxDetailFile+1)), new(any)); status != capacity {
		t.Fatalf("unbounded JSON: %v", status)
	}
}

func TestNativeFailuresDiscardPartialDetails(t *testing.T) {
	run := func(_ context.Context, selected backend, consume func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
		var data string
		switch selected.name {
		case "lsblk":
			data = `{"blockdevices":[]}`
		case "ip":
			data = `[]`
		case "flatpak":
			data = "org.example.App\t1\tx86_64\n"
		default:
			t.Fatalf("unexpected tool %q", selected.name)
		}
		if status := consume(strings.NewReader(data)); status != success {
			t.Fatalf("fixture parse: %v", status)
		}
		return commandFailure
	}
	if got := collectStorage(context.Background(), detailSources{run: run}); got.Status != commandFailure || len(got.Devices) != 0 {
		t.Fatalf("partial storage: %v", got)
	}
	if got := collectNetwork(context.Background(), run); got.Status != commandFailure || len(got.Interfaces) != 0 {
		t.Fatalf("partial network: %v", got)
	}
	if got := collectFlatpak(context.Background(), run); got.Status != commandFailure || len(got.Applications) != 0 {
		t.Fatalf("partial applications: %v", got)
	}
}

func TestARMPhysicalCoreTopology(t *testing.T) {
	// Constructed ARM native-format fixture: SMT siblings share a core while
	// a second package reuses core_id zero. Missing model stays unavailable.
	data := []byte("processor : 0\nFeatures : fp asimd\n\nprocessor : 1\nFeatures : fp asimd\n\nprocessor : 2\nFeatures : fp asimd\n")
	root := t.TempDir()
	for _, cpu := range []struct{ id, packageID string }{{"0", "0"}, {"1", "0"}, {"2", "1"}} {
		base := filepath.Join(root, "sys/devices/system/cpu/cpu"+cpu.id+"/topology")
		if err := os.MkdirAll(base, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, "physical_package_id"), []byte(cpu.packageID+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, "core_id"), []byte("0\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	sources := fixtureDetails(root)
	got := collectCPU(context.Background(), sources, data, nil)
	if got.LogicalCores.Value != 3 || got.PhysicalCores.Value != 2 || got.Model.Status != unavailable || got.X86_64Level.Status != unavailable {
		t.Fatalf("ARM topology: %v", got)
	}
	path := filepath.Join(root, "sys/devices/system/cpu/cpu1/topology/core_id")
	if err := os.WriteFile(path, []byte("-1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := collectCPU(context.Background(), sources, data, nil); got.PhysicalCores.Status != unavailable || got.PhysicalCores.Value != 0 {
		t.Fatalf("unknown topology published partial count: %v", got)
	}
	sources.readFile = func(string) ([]byte, error) { return nil, fs.ErrPermission }
	if got := collectCPU(context.Background(), sources, data, nil); got.PhysicalCores.Status != inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED {
		t.Fatalf("denied topology: %v", got)
	}
}

func TestApplicationNativeFailurePrecedence(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want inventoryv1.CollectionStatus
	}{
		{"empty-failure", commandFailure},
		{"empty-warning", commandFailure},
		{"empty-clean", success},
		{"invalid-failure", commandFailure},
		{"invalid-clean", invalid},
		{"valid-warning", commandFailure},
		{"capacity", capacity},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			run := func(ctx context.Context, _ backend, consume func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
				cmd := exec.CommandContext(ctx, executable, "-test.run=^TestApplicationSubprocessHelper$")
				cmd.Env = []string{"LINDM_APPLICATION_HELPER=" + tc.mode, "LANG=C", "LC_ALL=C"}
				cmd.Dir = "/"
				cmd.WaitDelay = time.Second
				return runCommand(ctx, cmd, consume)
			}
			got := collectFlatpak(ctx, run)
			if got.Status != tc.want || len(got.Applications) != 0 {
				t.Fatalf("status=%s want=%s applications=%v", got.Status, tc.want, got.Applications)
			}
		})
	}
}

func TestApplicationSubprocessHelper(t *testing.T) {
	mode := os.Getenv("LINDM_APPLICATION_HELPER")
	if mode == "" {
		return
	}
	var output, diagnostic string
	exit := 0
	switch mode {
	case "empty-failure":
		exit = 7
	case "empty-warning":
		diagnostic = "native service refused observation\n"
	case "empty-clean":
	case "invalid-failure":
		output, exit = "malformed native output\n", 7
	case "invalid-clean":
		output = "malformed native output\n"
	case "valid-warning":
		output = "org.example.App\t1\tx86_64\n"
		diagnostic = "native record ignored\n"
	case "capacity":
		output = strings.Repeat("x", maxDetailFile+1)
	default:
		os.Exit(8)
	}
	if _, err := io.WriteString(os.Stdout, output); err != nil {
		os.Exit(9)
	}
	if _, err := io.WriteString(os.Stderr, diagnostic); err != nil {
		os.Exit(9)
	}
	os.Exit(exit)
}

type applicationReadFailure struct{}

func (applicationReadFailure) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func TestApplicationReadFailureIsNotDeferred(t *testing.T) {
	run := func(_ context.Context, _ backend, consume func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
		status := consume(applicationReadFailure{})
		if status != invalid {
			t.Fatalf("read failure was deferred: %s", status)
		}
		return status
	}
	if got := collectFlatpak(t.Context(), run); got.Status != invalid || len(got.Applications) != 0 {
		t.Fatalf("read failure observation: %v", got)
	}
}
