//go:build linux

package passwordprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/nativeexec"
	"lindm/internal/agent/nativefile"
	"lindm/internal/custody"
)

type commandRunner func(context.Context, string, ...string) ([]byte, error)

func runNative(ctx context.Context, path string, args ...string) ([]byte, error) {
	result, err := nativeexec.Run(ctx, nativeexec.Command{Path: path, Args: args, Env: []string{"DEBIAN_FRONTEND=noninteractive"}, Timeout: 30 * time.Second, StdoutLimit: 65536, StderrLimit: 65536})
	if err != nil {
		return nil, fmt.Errorf("password native %s: %w", filepath.Base(path), err)
	}
	return result.Stdout, nil
}

// unsupported maps a custody refusal onto the provider's ErrUnsupported.
func unsupported(err error) error {
	if errors.Is(err, custody.ErrUnsafe) {
		return errors.Join(ErrUnsupported, err)
	}
	return err
}

// readNative reads a root-protected native file. Distribution builds hardlink
// identical vendor files (Fedora's authselect profiles); a root-owned,
// non-writable regular file is safe at any link count.
func readNative(path string, limit int64) ([]byte, error) {
	data, err := custody.ReadRoot(path, limit, true)
	return data, unsupported(err)
}

// readOSRelease reads the vendor os-release through root-owned symlinks only:
// Pop!_OS 24.04 ships /usr/lib/os-release -> ../../etc/pop-os/os-release, which
// readNative's no-follow open refused (ELOOP) on every password action.
func readOSRelease(path string) ([]byte, error) {
	data, err := custody.ReadResolvedRoot(path, 32768)
	return data, unsupported(err)
}
func digestMessage(m proto.Message) ([]byte, error) {
	b, err := (proto.MarshalOptions{Deterministic: true}).Marshal(m)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(b)
	return h[:], nil
}
func productSupported(p *resourcev1.PlatformProduct) bool {
	_, ok := pinnedVersions(p)
	return ok
}
func checkPlatform(p *resourcev1.PlatformProduct) error {
	if !productSupported(p) {
		return ErrUnsupported
	}
	for _, marker := range []string{"/run/ostree-booted", "/etc/NIXOS", "/etc/transactional-update.conf"} {
		if _, err := os.Stat(marker); err == nil {
			return ErrUnsupported
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	content, err := readOSRelease("/usr/lib/os-release")
	if err != nil {
		return err
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(content), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[key] = strings.Trim(value, "\"")
		}
	}
	if values["ID"] != p.GetOsId() || values["VERSION_ID"] != p.GetVersion() {
		return ErrUnsupported
	}
	return nil
}
func accessGuard(ctx context.Context, config *agentv1.NativePasswordProviderConfig, run commandRunner) error {
	if config == nil || !config.GetEnabled() || config.GetRecoverySessionId() == "" {
		return ErrAccessGuard
	}
	out, err := run(ctx, "/usr/bin/loginctl", "show-session", config.GetRecoverySessionId(), "--property=Active", "--property=State", "--property=User", "--property=Leader")
	if err != nil {
		return errors.Join(ErrAccessGuard, err)
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok || values[k] != "" {
			return ErrAccessGuard
		}
		values[k] = v
	}
	pid, err := strconv.ParseUint(values["Leader"], 10, 32)
	if err != nil || pid <= 1 || values["Active"] != "yes" || values["State"] != "active" || values["User"] != "0" {
		return ErrAccessGuard
	}
	return nil
}

func hashRecord(h hash.Hash, name string, content []byte, present bool) {
	var frame [17]byte
	binary.BigEndian.PutUint64(frame[:8], uint64(len(name)))
	binary.BigEndian.PutUint64(frame[8:16], uint64(len(content)))
	if present {
		frame[16] = 1
	}
	h.Write(frame[:])
	h.Write([]byte(name))
	h.Write(content)
}
func authselectSelection(raw []byte) ([]string, error) {
	parts := strings.Fields(string(raw))
	if len(parts) == 0 || len(parts) > 64 {
		return nil, ErrUnsupported
	}
	for i, part := range parts {
		name := part
		if i == 0 {
			name = strings.TrimPrefix(name, "custom/")
		}
		if name == "" || name[0] == '-' || len(name) > 128 {
			return nil, ErrUnsupported
		}
		for _, c := range name {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' && c != '-' {
				return nil, ErrUnsupported
			}
		}
		if slices.Contains(parts[:i], part) {
			return nil, ErrUnsupported
		}
	}
	return parts, nil
}

type managerState struct {
	profile                   string
	features                  []agentv1.PasswordNativeFeature
	generation, profileDigest []byte
	stacks                    map[string][]byte
}

func inspectManager(ctx context.Context, platform *resourcev1.PlatformProduct, run commandRunner) (*managerState, error) {
	if !productSupported(platform) {
		return nil, ErrUnsupported
	}
	if nativePAMProduct(platform) {
		return inspectNativePAM()
	}
	if pamConfigProduct(platform) {
		return inspectPamConfig(ctx, run)
	}
	state := &managerState{stacks: make(map[string][]byte)}
	graph := sha256.New()
	profileHash := sha256.New()
	if authselectProduct(platform) {
		if _, err := run(ctx, "/usr/bin/authselect", "check"); err != nil {
			return nil, fmt.Errorf("%w: authselect stack integrity: %v", ErrUnsupported, err)
		}
		raw, err := run(ctx, "/usr/bin/authselect", "current", "--raw")
		if err != nil {
			return nil, err
		}
		parts, err := authselectSelection(raw)
		if err != nil {
			return nil, err
		}
		state.profile = parts[0]
		name := state.profile
		base := "/usr/share/authselect/default/"
		if custom, ok := strings.CutPrefix(name, "custom/"); ok {
			name = custom
			base = "/etc/authselect/custom/"
		} else {
			info, err := os.Lstat("/usr/share/authselect/vendor/" + name)
			if err == nil {
				if !info.IsDir() {
					return nil, ErrUnsupported
				}
				base = "/usr/share/authselect/vendor/"
			} else if !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
		}
		hashRecord(profileHash, "profile-source", []byte(base+name), true)
		for _, feature := range parts[1:] {
			switch feature {
			case "with-faillock":
				state.features = append(state.features, 3)
			case "with-pwhistory":
				state.features = append(state.features, 2)
			}
		}
		for _, file := range []string{"system-auth", "password-auth"} {
			template, err := readNative(base+name+"/"+file, 32768)
			if err != nil {
				return nil, err
			}
			hashRecord(profileHash, file, template, true)
			link, err := os.Readlink("/etc/pam.d/" + file)
			if err != nil {
				return nil, ErrUnsupported
			}
			if link != "/etc/authselect/"+file && link != "../authselect/"+file {
				return nil, ErrUnsupported
			}
			content, err := readNative("/etc/authselect/"+file, 32768)
			if err != nil {
				return nil, err
			}
			state.stacks[file] = content
			hashRecord(graph, file, content, true)
		}
		for _, file := range []string{"fingerprint-auth", "smartcard-auth", "switchable-auth", "postlogin", "nsswitch.conf", "dconf-db", "dconf-locks"} {
			template, err := readNative(base+name+"/"+file, 32768)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
			hashRecord(profileHash, file, template, err == nil)
			content, err := readNative("/etc/authselect/"+file, 32768)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
			hashRecord(graph, file, content, err == nil)
		}
		userNSS, err := readNative("/etc/authselect/user-nsswitch.conf", 32768)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		hashRecord(profileHash, "user-nsswitch.conf", userNSS, err == nil)
		hashRecord(graph, "selection", raw, true)
	} else {
		state.profile = "pam-auth-update"
		info, err := os.Stat("/usr/sbin/pam-auth-update")
		if err != nil || !info.Mode().IsRegular() {
			return nil, ErrUnsupported
		}
		for _, file := range []string{"common-auth", "common-account", "common-password", "common-session", "common-session-noninteractive"} {
			content, err := readNative("/etc/pam.d/"+file, 32768)
			if err != nil {
				return nil, err
			}
			if !bytes.Contains(content, []byte("pam-auth-update")) || !bytes.Contains(content, []byte("# end of pam-auth-update config")) {
				return nil, fmt.Errorf("%w: unmanaged PAM stack", ErrUnsupported)
			}
			state.stacks[file] = content
			hashRecord(graph, file, content, true)
		}
		// Compare the manager's module cache, not whole files: /var/lib/pam stores
		// Module records and symbolic end jumps rather than generated PAM text.
		for _, file := range []string{"auth", "account", "password", "session", "session-noninteractive"} {
			cached, err := readNative("/var/lib/pam/"+file, 32768)
			if err != nil {
				return nil, err
			}
			if !cacheMatches(cached, state.stacks["common-"+file]) {
				return nil, fmt.Errorf("%w: PAM manager cache differs", ErrUnsupported)
			}
			hashRecord(graph, "cache/"+file, cached, true)
		}
		enabled, err := readNative("/var/lib/pam/seen", 32768)
		if err != nil {
			return nil, err
		}
		hashRecord(graph, "seen", enabled, true)
		profiles, err := os.ReadDir("/usr/share/pam-configs")
		if err != nil {
			return nil, err
		}
		if len(profiles) > 128 {
			return nil, ErrUnsupported
		}
		seen := strings.Fields(string(enabled))
		for _, entry := range profiles {
			name := entry.Name()
			if strings.HasSuffix(name, "~") || (strings.HasPrefix(name, "#") && strings.HasSuffix(name, "#")) {
				continue
			}
			switch name {
			case "lindm-pwquality", "lindm-pwhistory", "lindm-faillock", "lindm-faillock-pre":
				continue
			}
			if !slices.Contains(seen, name) {
				return nil, fmt.Errorf("%w: unseen package PAM profile", ErrUnsupported)
			}
			content, err := readNative("/usr/share/pam-configs/"+name, 32768)
			if err != nil {
				return nil, err
			}
			hashRecord(profileHash, name, content, true)
		}
	}
	active, err := inspectStacks(state.stacks)
	if err != nil {
		return nil, err
	}
	if authselectProduct(platform) {
		for _, f := range state.features {
			if !slices.Contains(active, f) {
				return nil, ErrUnsupported
			}
		}
	}
	if authselectProduct(platform) {
		for name, stack := range state.stacks {
			features, err := inspectStacks(map[string][]byte{name: stack})
			if err != nil {
				return nil, err
			}
			if !slices.Equal(features, active) {
				return nil, fmt.Errorf("%w: inconsistent authselect entry stacks", ErrUnsupported)
			}
		}
	}
	state.features = active
	slices.Sort(state.features)
	state.generation = graph.Sum(nil)
	state.profileDigest = profileHash.Sum(nil)
	return state, nil
}

// inspectStacks recognizes the native module semantics and refuses arguments
// which would shadow the supported configuration files. Includes in the managed
// common stacks are deliberately unsupported rather than treated as effective.
func inspectStacks(stacks map[string][]byte) ([]agentv1.PasswordNativeFeature, error) {
	quality, history, pre, fail, success := false, false, false, false, false
	for _, content := range stacks {
		bypass := map[string]bool{}
		localHistoryGuard := false
		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
			if line == "" {
				continue
			}
			tokens := strings.Fields(line)
			if len(tokens) < 3 || tokens[0] == "@include" {
				return nil, ErrUnsupported
			}
			at := -1
			for i, t := range tokens {
				if strings.HasSuffix(t, ".so") {
					at = i
					break
				}
			}
			if at < 0 {
				return nil, fmt.Errorf("%w: nested PAM stack", ErrUnsupported)
			}
			module := tokens[at]
			if strings.Contains(module, "/") {
				return nil, ErrUnsupported
			}
			if at < 2 {
				return nil, ErrUnsupported
			}
			control := strings.Join(tokens[1:at], " ")
			stackType := strings.TrimPrefix(tokens[0], "-")
			if module != "pam_pwquality.so" && module != "pam_pwhistory.so" && module != "pam_faillock.so" {
				// pam_localuser's default=1 skips history for directory accounts only.
				localOnly := module == "pam_localuser.so" && control == "[default=1 ignore=ignore success=ok]" && len(tokens) == at+1
				localHistoryGuard = localOnly && stackType == "password"
				if !localOnly && (control == "sufficient" || strings.HasPrefix(control, "[")) {
					bypass[stackType] = true
				}
				continue
			}
			guarded := module == "pam_pwquality.so" || module == "pam_pwhistory.so" || stackType == "account" || slices.Contains(tokens[at+1:], "preauth")
			if guarded && bypass[stackType] {
				return nil, fmt.Errorf("%w: PAM control can bypass local policy", ErrUnsupported)
			}
			if control != "required" && control != "requisite" && control != "[default=die]" {
				return nil, fmt.Errorf("%w: non-enforcing PAM module", ErrUnsupported)
			}
			for _, arg := range tokens[at+1:] {
				allowed := false
				switch module {
				case "pam_pwquality.so":
					allowed = arg == "retry=3" || arg == "use_authtok" || arg == "local_users_only"
				case "pam_pwhistory.so":
					allowed = arg == "retry=3" || arg == "use_authtok"
				case "pam_faillock.so":
					allowed = arg == "preauth" || arg == "authfail" || arg == "authsucc" || arg == "silent" || arg == "local_users_only"
				}
				if !allowed {
					return nil, fmt.Errorf("%w: PAM argument overrides config", ErrUnsupported)
				}
			}
			if module == "pam_pwhistory.so" && !localHistoryGuard {
				return nil, fmt.Errorf("%w: password history lacks exact local-user guard", ErrUnsupported)
			}
			localHistoryGuard = false
			switch module {
			case "pam_pwquality.so":
				if tokens[0] != "password" {
					return nil, ErrUnsupported
				}
				quality = true
			case "pam_pwhistory.so":
				if tokens[0] != "password" {
					return nil, ErrUnsupported
				}
				history = true
			case "pam_faillock.so":
				if tokens[0] == "account" || slices.Contains(tokens[at+1:], "authsucc") {
					success = true
				}
				pre = pre || slices.Contains(tokens[at+1:], "preauth")
				fail = fail || slices.Contains(tokens[at+1:], "authfail")
			}
		}
	}
	var active []agentv1.PasswordNativeFeature
	if quality {
		active = append(active, 1)
	}
	if history {
		active = append(active, 2)
	}
	if pre || fail || success {
		if !pre || !fail || !success {
			return nil, fmt.Errorf("%w: incomplete faillock flow", ErrUnsupported)
		}
		active = append(active, 3)
	}
	return active, nil
}
func moduleDirectory(platform *resourcev1.PlatformProduct) string {
	if authselectProduct(platform) || pamConfigProduct(platform) {
		return "/usr/lib64/security/"
	}
	if nativePAMProduct(platform) {
		return "/usr/lib/security/"
	}
	switch runtime.GOARCH {
	case "amd64":
		return "/usr/lib/x86_64-linux-gnu/security/"
	case "arm64":
		return "/usr/lib/aarch64-linux-gnu/security/"
	default:
		return ""
	}
}
func moduleName(feature agentv1.PasswordNativeFeature) string {
	switch feature {
	case 1:
		return "pam_pwquality.so"
	case 2:
		return "pam_pwhistory.so"
	case 3:
		return "pam_faillock.so"
	default:
		return ""
	}
}
func observeModules(ctx context.Context, platform *resourcev1.PlatformProduct, features []agentv1.PasswordNativeFeature, run commandRunner) ([]*resourcev1.NativeModuleVersion, []byte, error) {
	var modules []*resourcev1.NativeModuleVersion
	hash := sha256.New()
	directory := moduleDirectory(platform)
	if directory == "" {
		return nil, nil, ErrUnsupported
	}
	versions := make(map[string]string, 2)
	for _, feature := range features {
		digest, err := moduleDigest(directory + moduleName(feature))
		if err != nil {
			return nil, nil, missingModule(platform, feature, err)
		}
		name := modulePackageName(platform, feature)
		version := versions[name]
		if version == "" {
			version, err = packageVersion(ctx, platform, name, run)
			if err != nil {
				return nil, nil, missingModule(platform, feature, err)
			}
			versions[name] = version
		}
		if !moduleVersionSupported(platform, feature, version) {
			return nil, nil, fmt.Errorf("%w: unsupported PAM module package version", ErrUnsupported)
		}
		if feature == 1 && pamConfigProduct(platform) {
			library, err := packageVersion(ctx, platform, "libpwquality1", run)
			if err != nil {
				return nil, nil, err
			}
			if library != version {
				return nil, nil, fmt.Errorf("%w: libpwquality and PAM module package releases differ", ErrUnsupported)
			}
			modules = append(modules, &resourcev1.NativeModuleVersion{Name: "libpwquality1", Version: library})
		}
		hash.Write([]byte(moduleName(feature)))
		hash.Write(digest)
		modules = append(modules, &resourcev1.NativeModuleVersion{Name: moduleName(feature), Version: version})
		if feature == 2 {
			localDigest, err := moduleDigest(directory + "pam_localuser.so")
			if err != nil {
				prerequisite := missingModule(platform, feature, err)
				prerequisite.Module = "pam_localuser.so"
				return nil, nil, prerequisite
			}
			hash.Write([]byte("pam_localuser.so"))
			hash.Write(localDigest)
			modules = append(modules, &resourcev1.NativeModuleVersion{Name: "pam_localuser.so", Version: version})
		}
	}
	return modules, hash.Sum(nil), nil
}
func moduleDigest(path string) (digest []byte, err error) {
	file, stat, err := custody.OpenRoot(path, unix.O_RDONLY)
	if err != nil {
		return nil, unsupported(err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, errors.Join(ErrUnsupported, file.Close())
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	var magic [4]byte
	if _, err := io.ReadFull(file, magic[:]); err != nil {
		return nil, err
	}
	if magic != [4]byte{0x7f, 'E', 'L', 'F'} {
		return nil, ErrUnsupported
	}
	h := sha256.New()
	h.Write(magic[:])
	size, err := io.Copy(h, io.LimitReader(file, (4<<20)-3))
	if err != nil {
		return nil, err
	}
	if size > (4<<20)-4 {
		return nil, ErrUnsupported
	}
	return h.Sum(nil), nil
}
func effectivePolicy(s *agentv1.ResourceOwnershipSnapshot, dropins map[string]string) (*resourcev1.PasswordPolicyDesired, error) {
	configs := make(map[agentv1.PasswordNativeFile]map[string]string)
	for kind := agentv1.PasswordNativeFile(1); kind <= 4; kind++ {
		f := nativeFile(s, kind)
		if f == nil {
			return nil, ErrUnsupported
		}
		values, err := parseConfig(f.GetContent(), kind == 4)
		if err != nil {
			return nil, err
		}
		if kind == 1 {
			merged := make(map[string]string, len(dropins)+len(values))
			for k, v := range dropins {
				merged[k] = v
			}
			for k, v := range values {
				merged[k] = v
			}
			values = merged
		}
		configs[kind] = values
	}
	if configs[1]["enforcing"] == "0" || configs[3]["even_deny_root"] != "" || configs[3]["root_unlock_time"] != "" {
		return nil, fmt.Errorf("%w: unsafe or non-enforcing PAM configuration", ErrUnsupported)
	}
	for key, value := range configs[2] {
		switch key {
		case "debug", "enforce_for_root", "remember":
		case "retry":
			if value != "3" {
				return nil, ErrUnsupported
			}
		case "file":
			if value != "/etc/security/opasswd" {
				return nil, ErrUnsupported
			}
		default:
			return nil, fmt.Errorf("%w: unsupported pwhistory control", ErrUnsupported)
		}
	}
	for key, value := range configs[3] {
		switch key {
		case "deny", "unlock_time", "audit", "silent", "no_log_info", "nodelay", "local_users_only":
		case "dir":
			if value != "/run/faillock" && value != "/var/run/faillock" {
				return nil, ErrUnsupported
			}
		case "fail_interval":
			seconds, err := strconv.ParseUint(value, 10, 32)
			if err != nil || seconds == 0 || seconds > 604800 {
				return nil, ErrUnsupported
			}
		default:
			return nil, fmt.Errorf("%w: unsupported faillock control", ErrUnsupported)
		}
	}
	for key, value := range configs[1] {
		switch key {
		case "badwords", "dictpath", "enforce_for_root", "local_users_only":
		case "difok", "minlen", "dcredit", "ucredit", "lcredit", "ocredit", "minclass", "maxrepeat", "maxclassrepeat", "maxsequence", "gecoscheck", "dictcheck", "usercheck", "usersubstr", "enforcing", "retry":
			number, err := strconv.ParseInt(value, 10, 32)
			if err != nil || number == 2147483647 || number == -2147483648 {
				return nil, ErrUnsupported
			}
			if number < 0 && key != "dcredit" && key != "ucredit" && key != "lcredit" && key != "ocredit" {
				return nil, ErrUnsupported
			}
		default:
			return nil, fmt.Errorf("%w: unknown libpwquality control", ErrUnsupported)
		}
	}
	result := &resourcev1.PasswordPolicyDesired{}
	m := result.ProtoReflect()
	defaults := []uint64{8, 0, 10, 99999, 0, 7, 3, 600, 0}
	for n := 1; n <= 9; n++ {
		field := resourcev1.PasswordField(n)
		feature := featureFor(field)
		if feature != 0 && !slices.Contains(s.PasswordPolicy.EnabledFeatures, feature) {
			continue
		}
		spec := settingFor(field)
		value, present := configs[spec.file][spec.keys[0]]
		fd := m.Descriptor().Fields().ByNumber(protoreflect.FieldNumber(n))
		if field == 9 {
			_, historyRoot := configs[2]["enforce_for_root"]
			m.Set(fd, protoreflect.ValueOfBool(present && (!slices.Contains(s.PasswordPolicy.EnabledFeatures, agentv1.PasswordNativeFeature_PASSWORD_NATIVE_FEATURE_HISTORY) || historyRoot)))
			continue
		}
		v := defaults[n-1]
		if present {
			if field == 8 && value == "never" {
				value = "0"
			}
			parsed, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("%w: unrepresentable native value", ErrUnsupported)
			}
			v = parsed
		}
		if field == 1 && v < 6 {
			v = 6
		}
		m.Set(fd, protoreflect.ValueOfUint32(uint32(v)))
	}
	// A positive credit makes minlen a score, not the declared character count.
	if result.MinLength != nil {
		for _, key := range []string{"dcredit", "ucredit", "lcredit", "ocredit"} {
			value := configs[1][key]
			if value != "" && value != "0" {
				result.MinLength = nil
			}
		}
	}
	return result, nil
}
func readQualityDropins() (map[string]string, []byte, error) {
	values := make(map[string]string)
	hash := sha256.New()
	// Vendor builds can select /usr/lib when the administrator file is absent.
	// Never replace an active vendor policy with inferred defaults.
	vendor, err := readNative("/usr/lib/security/pwquality.conf", 32768)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	hashRecord(hash, "vendor/pwquality.conf", vendor, err == nil)
	if err == nil {
		_, localErr := os.Lstat(filePath(1))
		if errors.Is(localErr, os.ErrNotExist) {
			settings, err := parseConfig(vendor, false)
			if err != nil {
				return nil, nil, err
			}
			if len(settings) != 0 {
				return nil, nil, fmt.Errorf("%w: provision vendor quality policy in /etc before adoption", ErrUnsupported)
			}
		} else if localErr != nil {
			return nil, nil, localErr
		}
	}
	entries, err := os.ReadDir("/etc/security/pwquality.conf.d")
	if errors.Is(err, os.ErrNotExist) {
		return values, hash.Sum(nil), nil
	}
	if err != nil {
		return nil, nil, err
	}
	if len(entries) > 128 {
		return nil, nil, ErrUnsupported
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		if entry.IsDir() {
			return nil, nil, ErrUnsupported
		}
		content, err := readNative("/etc/security/pwquality.conf.d/"+entry.Name(), 32768)
		if err != nil {
			return nil, nil, err
		}
		parsed, err := parseConfig(content, false)
		if err != nil {
			return nil, nil, err
		}
		for k, v := range parsed {
			values[k] = v
		}
		hashRecord(hash, entry.Name(), content, true)
	}
	return values, hash.Sum(nil), nil
}
func (p *Provider) snapshot(ctx context.Context, d *resourcev1.PasswordPolicyDesired) (*agentv1.ResourceOwnershipSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	manager, err := inspectManager(ctx, p.config.Platform, p.run)
	if err != nil {
		return nil, err
	}
	version, err := managerVersion(ctx, p.config.Platform, p.run)
	if err != nil {
		return nil, err
	}
	if version != p.backend.GetNativeVersion() {
		return nil, ErrConflict
	}
	needed := neededFeatures(d)
	for _, f := range manager.features {
		if !slices.Contains(needed, f) {
			needed = append(needed, f)
		}
	}
	slices.Sort(needed)
	modules, moduleHash, err := observeModules(ctx, p.config.Platform, needed, p.run)
	if err != nil {
		return nil, err
	}
	boot, err := readNative("/proc/sys/kernel/random/boot_id", 128)
	if err != nil {
		return nil, err
	}
	observed := &resourcev1.ResourceObservation{Ref: passwordRef(), Metadata: &resourcev1.ObservationMetadata{BootId: strings.TrimSpace(string(boot)), ExecutorIncarnation: p.config.ExecutorIncarnation, ObservedAt: timestamppb.Now(), Backend: proto.CloneOf(p.backend), NativeRevision: make([]byte, 32), ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK}}
	result := &agentv1.ResourceOwnershipSnapshot{Observation: observed, PasswordPolicy: &agentv1.PasswordPolicyOwnership{ManagerProfile: manager.profile, ManagerGenerationSha256: manager.generation, ManagerProfileSha256: manager.profileDigest, EnabledFeatures: manager.features}}
	kinds := []agentv1.PasswordNativeFile{1, 2, 3, 4}
	switch passwordBackend(p.config.Platform) {
	case resourcev1.Backend_BACKEND_PAM_AUTH_UPDATE:
		kinds = append(kinds, 5, 6, 7, 8)
	case resourcev1.Backend_BACKEND_NATIVE_PAM:
		kinds = append(kinds, 9, 10)
	case resourcev1.Backend_BACKEND_PAM_CONFIG:
		kinds = append(kinds, 11)
	}
	for _, kind := range kinds {
		file, err := nativefile.Capture(filePath(kind), observed)
		if err != nil {
			return nil, err
		}
		if kind == 11 && file.GetObservation().GetManagedFile().GetExists() && !bytes.Equal(file.GetManagedFileContent(), manager.stacks["common-password"]) {
			return nil, ErrConflict
		}
		result.PasswordPolicy.Files = append(result.PasswordPolicy.Files, &agentv1.PasswordNativeFileSnapshot{Kind: kind, State: proto.CloneOf(file.GetObservation().GetManagedFile()), Content: bytes.Clone(file.GetManagedFileContent()), Xattrs: file.GetManagedFileXattrs(), NativeRevisionSha256: bytes.Clone(file.GetObservation().GetMetadata().GetNativeRevision())})
	}
	dropins, dropHash, err := readQualityDropins()
	if err != nil {
		return nil, err
	}
	result.PasswordPolicy.QualityDropinsSha256 = dropHash
	effective, err := effectivePolicy(result, dropins)
	if err != nil {
		return nil, err
	}
	privateDigest, err := digestMessage(result.GetPasswordPolicy())
	if err != nil {
		return nil, err
	}
	configHash := sha256.New()
	configHash.Write([]byte("lindm.password.configuration.v1\x00"))
	configHash.Write(privateDigest)
	configHash.Write(moduleHash)
	observed.Observed = &resourcev1.ResourceObservation_PasswordPolicy{PasswordPolicy: &resourcev1.PasswordPolicyObservation{PamOwner: manager.profile, Effective: effective, Modules: modules, ConfigurationSha256: configHash.Sum(nil)}}
	digest, err := digestMessage(observed.GetPasswordPolicy())
	if err != nil {
		return nil, err
	}
	observed.Metadata.NativeRevision = digest
	return result, nil
}

func cacheMatches(cache, stack []byte) bool {
	var saved, current []string
	normalize := func(line string) string {
		tokens := strings.Fields(line)
		for i, token := range tokens {
			key, value, ok := strings.Cut(token, "=")
			if !ok {
				continue
			}
			suffix := ""
			if strings.HasSuffix(value, "]") {
				value = strings.TrimSuffix(value, "]")
				suffix = "]"
			}
			_, err := strconv.ParseUint(value, 10, 32)
			if value == "end" || err == nil {
				tokens[i] = key + "=" + suffix
			}
		}
		return strings.Join(tokens, " ")
	}
	for _, line := range strings.Split(string(cache), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "Module: ") {
			continue
		}
		saved = append(saved, normalize(line))
	}
	inside := false
	for _, line := range strings.Split(string(stack), "\n") {
		if strings.HasPrefix(line, "# here are the per-package modules") || strings.HasPrefix(line, "# and here are more per-package modules") {
			inside = true
			continue
		}
		if strings.HasPrefix(line, "# here's the fallback") || strings.HasPrefix(line, "# end of pam-auth-update config") {
			inside = false
			continue
		}
		if !inside || strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		tokens := strings.Fields(line)
		if len(tokens) < 3 {
			return false
		}
		current = append(current, normalize(strings.Join(tokens[1:], " ")))
	}
	return len(saved) > 0 && slices.Equal(saved, current)
}
