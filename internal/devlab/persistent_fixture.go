package devlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/config"
	"lindm/internal/custody"
	"lindm/internal/labexec"
	"lindm/internal/releaseupdate"
)

// OpenPersistentFixture creates or resumes a local held-demo authority. Close
// stops only lindmd; DestroyPersistentFixture is the sole destructive operation.
// Options apply at creation; resume uses the retained configuration and settings.
func OpenPersistentFixture(ctx context.Context, repository, binary, stateDir string, options LoadAuthorityOptions) (*AuthorityFixture, error) {
	return openPersistentFixture(ctx, repository, binary, stateDir, netip.Addr{}, options)
}

// OpenPersistentSplitFixture keeps the console on loopback and signs the routed
// device address into private trust. Resume refuses address changes or busy ports.
func OpenPersistentSplitFixture(ctx context.Context, repository, binary, stateDir string, device netip.Addr, options LoadAuthorityOptions) (*AuthorityFixture, error) {
	if err := validateSplitDevice(device); err != nil {
		return nil, err
	}
	return openPersistentFixture(ctx, repository, binary, stateDir, device, options)
}

func openPersistentFixture(ctx context.Context, repository, binary, stateDir string, device netip.Addr, options LoadAuthorityOptions) (_ *AuthorityFixture, resultErr error) {
	if err := options.validate(); err != nil {
		return nil, err
	}
	if options.DatabaseStorage != "" && options.DatabaseStorage != "shared" || options.ListenAddress != "" {
		return nil, errors.New("persistent fixtures require shared durable PostgreSQL and topology-owned listener addresses")
	}
	dir, lock, fresh, err := lockPersistentDirectory(stateDir, true)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, lock.Close())
		}
	}()
	if fresh {
		if err := writePersistentJSON(filepath.Join(dir, "fixture.json"), 1); err != nil {
			return nil, err
		}
		if err := writePersistentJSON(filepath.Join(dir, "options.json"), options); err != nil {
			return nil, err
		}
		options.splitDevice, options.persistentDirectory = device, dir
		f, err := openAuthorityFixtureWithOptions(ctx, repository, binary, authorityDeviceActions, options)
		if err != nil {
			return nil, err
		}
		if err := writePersistentJSON(filepath.Join(dir, "native-repository.json"), f.NativeRepository); err != nil {
			return nil, errors.Join(err, f.Close())
		}
		if err := writePersistentJSON(filepath.Join(dir, "ready.json"), true); err != nil {
			return nil, errors.Join(err, f.Close())
		}
		f.stateLock = lock
		return f, nil
	}
	var ready bool
	if err := readPersistentJSON(filepath.Join(dir, "ready.json"), &ready); err != nil || !ready {
		return nil, fmt.Errorf("persistent fixture initialization incomplete; destroy explicitly before recreating: %w", err)
	}
	var creationOptions LoadAuthorityOptions
	if err := readPersistentJSON(filepath.Join(dir, "options.json"), &creationOptions); err != nil {
		return nil, err
	}
	if err := creationOptions.validate(); err != nil {
		return nil, fmt.Errorf("persistent fixture creation options: %w", err)
	}
	root, err := filepath.Abs(repository)
	if err != nil {
		return nil, err
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return nil, err
	}
	f := &AuthorityFixture{
		repository: root, binary: binary, directory: dir, persistent: true, Resumed: true,
		serverCPUs: creationOptions.ServerCPUs,
		environment: LoadExperimentEnvironment{
			Storage: "storage: shared development PostgreSQL", ServerCPUs: creationOptions.ServerCPUs,
		},
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, f.Close())
		}
	}()
	if err := readPersistentJSON(filepath.Join(dir, "native-repository.json"), &f.NativeRepository); err != nil {
		return nil, err
	}
	if err := readPersistentJSON(filepath.Join(dir, "database.json"), &f.DatabaseName); err != nil {
		return nil, err
	}
	document, err := config.Load(f.configPath())
	if err != nil {
		return nil, err
	}
	cfg := document.Proto
	admin, err := authorityDatabaseAdminFor(document, dir, f.DatabaseName)
	if err != nil {
		return nil, err
	}
	f.database = &authorityDatabase{name: f.DatabaseName, admin: admin, created: true}
	expected := "127.0.0.1"
	if device.IsValid() {
		expected = device.String()
	}
	if cfg.GetAdminListener().GetAddress() != "127.0.0.1" || cfg.GetDeviceListener().GetAddress() != expected {
		return nil, errors.New("persistent fixture listener address changed; use its original topology and address")
	}
	f.AdminAddress = net.JoinHostPort("127.0.0.1", fmt.Sprint(cfg.GetAdminListener().GetPort()))
	f.DeviceAddress = net.JoinHostPort(expected, fmt.Sprint(cfg.GetDeviceListener().GetPort()))
	f.ConsoleOrigin, f.DeviceOrigin = cfg.GetPublicUrl(), cfg.GetDevicePublicUrl()
	if err := checkPersistentPorts(cfg); err != nil {
		return nil, err
	}
	if err := f.restoreLocalAccounts(); err != nil {
		return nil, err
	}
	signers, err := releaseupdate.LoadRoleSigners(filepath.Join(dir, "release-custody"), true)
	if err != nil {
		return nil, err
	}
	f.releasePublisher, err = releaseupdate.NewPublisher(releaseupdate.PublisherConfig{Directory: filepath.Join(dir, "release-repository"), Signers: signers, Now: time.Now})
	if err != nil {
		return nil, err
	}
	f.log, err = os.OpenFile(filepath.Join(dir, "server.log"), os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err := labexec.Run(ctx, labexec.Command{Path: binary, Args: []string{"migrate", "-config", f.configPath()}, Stdout: f.log, Stderr: f.log, Timeout: time.Minute}); err != nil {
		return nil, fmt.Errorf("migrate persistent fixture: %w", err)
	}
	if err := f.start(ctx); err != nil {
		return nil, err
	}
	f.stateLock = lock
	return f, nil
}

// DestroyPersistentFixture refuses a running fixture and drops only its recorded
// owned database, without FORCE. A failed drop retains all credentials and state.
// The drop's own lock and storage budgets apply unless ctx ends first.
func DestroyPersistentFixture(ctx context.Context, repository, stateDir string) (resultErr error) {
	dir, lock, _, err := lockPersistentDirectory(stateDir, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Close()) }()
	var version int
	if err := readPersistentJSON(filepath.Join(dir, "fixture.json"), &version); err != nil {
		return err
	}
	if version != 1 {
		return errors.New("unsupported persistent fixture state")
	}
	var name string
	if err := readPersistentJSON(filepath.Join(dir, "database.json"), &name); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return os.RemoveAll(dir)
		}
		return err
	}
	suffix, ok := strings.CutPrefix(name, "lindm_authority_")
	if _, err := uuid.Parse(suffix); !ok || err != nil || len(suffix) != 32 {
		return errors.New("persistent fixture database identity is not lab-owned")
	}
	document, err := config.Load(filepath.Join(dir, "server.json"))
	shared, expected := dir, name
	if err != nil || document.Proto.GetDatabase().GetUrlFile() != "database-url" {
		material, materialErr := ReadPublicAgentFixture(ctx, repository)
		if materialErr != nil {
			return errors.Join(err, materialErr)
		}
		document, err = authorityDocument(ctx, filepath.Join(dir, "destroy.json"), FixturePath(repository), material)
		if err != nil {
			return err
		}
		shared, expected = FixturePath(repository), "lindm"
		document.Proto.Database.MigrationUrlFile = proto.String(filepath.Join(shared, "migration-database-url"))
	}
	admin, err := authorityDatabaseAdminFor(document, shared, expected)
	if err != nil {
		return err
	}
	database := &authorityDatabase{name: name, admin: admin, created: true}
	dropContext, cancel := context.WithTimeout(ctx, dropBudget)
	defer cancel()
	if err := database.drop(dropContext, true, dropLockBudget); err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

// The lock is outside stateDir so destruction cannot unlink a lock inode while
// another process is acquiring it. It contains no state or credentials.
func lockPersistentDirectory(path string, create bool) (dir string, lock *os.File, fresh bool, resultErr error) {
	if path == "" {
		return "", nil, false, errors.New("persistent state directory is required")
	}
	dir, err := filepath.Abs(path)
	if err != nil {
		return "", nil, false, err
	}
	if create {
		if err := os.MkdirAll(filepath.Dir(dir), 0700); err != nil {
			return "", nil, false, err
		}
	}
	lock, err = os.OpenFile(dir+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return "", nil, false, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, lock.Close())
		}
	}()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return "", lock, false, fmt.Errorf("persistent state is in use: %w", err)
	}
	if create {
		err := os.Mkdir(dir, 0700)
		fresh = err == nil
		if err != nil && !errors.Is(err, os.ErrExist) {
			return "", lock, false, err
		}
	}
	if _, err := custody.Owned(dir, true); err != nil {
		return "", lock, false, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", lock, false, err
	}
	if info.Mode().Perm() != 0700 {
		return "", lock, false, errors.New("persistent state directory must have mode 0700")
	}
	return dir, lock, fresh, nil
}

func (f *AuthorityFixture) writeConfig(data []byte) error {
	if f.scaleOut != nil {
		return errors.New("configure all replica settings before scale-out")
	}
	return writePersistentFile(f.configPath(), data)
}

func writePersistentJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	defer clear(data)
	return writePersistentFile(path, data)
}

func writePersistentFile(path string, data []byte) (resultErr error) {
	file, err := os.CreateTemp(filepath.Dir(path), ".state-")
	if err != nil {
		return err
	}
	defer func() {
		if err := os.Remove(file.Name()); err != nil && !errors.Is(err, os.ErrNotExist) {
			resultErr = errors.Join(resultErr, err)
		}
	}()
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	if err := errors.Join(writeErr, syncErr, file.Close()); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func readPersistentJSON(path string, value any) error {
	data, err := readOwned(path)
	if err != nil {
		return err
	}
	defer clear(data)
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0600 {
		return errors.New("persistent credential state must have mode 0600")
	}
	return json.Unmarshal(data, value)
}

func checkPersistentPorts(cfg *configv1.ServerConfig) error {
	for _, listener := range []*configv1.ListenerConfig{cfg.GetAdminListener(), cfg.GetDeviceListener(), cfg.GetAssistance().GetRelay().GetListener()} {
		if listener == nil {
			continue
		}
		address := net.JoinHostPort(listener.GetAddress(), fmt.Sprint(listener.GetPort()))
		stream, err := net.Listen("tcp4", address)
		if err != nil {
			return fmt.Errorf("persistent listener %s unavailable: %w", address, err)
		}
		if err := stream.Close(); err != nil {
			return err
		}
		if listener == cfg.GetAssistance().GetRelay().GetListener() {
			packet, err := net.ListenPacket("udp4", address)
			if err != nil {
				return fmt.Errorf("persistent TURN listener %s unavailable: %w", address, err)
			}
			if err := packet.Close(); err != nil {
				return err
			}
		}
	}
	return nil
}

// AssistanceConfiguration returns the persisted relay contract, or nil before
// first configuration. Callers must reuse it rather than allocate new ports.
func (f *AuthorityFixture) AssistanceConfiguration() (*configv1.AssistanceConfig, error) {
	if f.closed || f.connected != nil {
		return nil, errors.New("assistance configuration requires an open controller fixture")
	}
	document, err := config.Load(f.configPath())
	if err != nil {
		return nil, err
	}
	return document.Proto.GetAssistance(), nil
}
