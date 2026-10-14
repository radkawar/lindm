// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package passwordprovider manages closed local PAM policy controls through
// distro managers or owned native includes and module configuration. Generated
// PAM stacks are never edited. login.defs affects defaults, not existing accounts.
// Effects require a guarded root helper and signed dimension ownership; partial
// effects remain UNKNOWN and are never automatically replayed.
package passwordprovider

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/platform"
	"lindm/internal/resource"
)

var (
	ErrUnsupported    = errors.New("passwordprovider: unsupported_native_policy")
	ErrMissingModule  = errors.New("passwordprovider: required_pam_package_missing")
	ErrConflict       = errors.New("passwordprovider: ownership_or_native_precondition_conflict")
	ErrOutcomeUnknown = errors.New("passwordprovider: native_outcome_unknown")
	ErrAccessGuard    = errors.New("passwordprovider: active_root_recovery_session_required")
	ErrNotConverged   = errors.Join(resource.ErrNotConverged, errors.New("passwordprovider: policy_not_converged"))
)

// The numeric fields deliberately follow the closed PasswordField schema.
type setting struct {
	file agentv1.PasswordNativeFile
	keys []string
}

func settingFor(field resourcev1.PasswordField) setting {
	switch field {
	case resourcev1.PasswordField_PASSWORD_FIELD_LENGTH:
		return setting{1, []string{"minlen", "dcredit", "ucredit", "lcredit", "ocredit", "local_users_only"}}
	case resourcev1.PasswordField_PASSWORD_FIELD_CLASSES:
		return setting{1, []string{"minclass", "local_users_only"}}
	case resourcev1.PasswordField_PASSWORD_FIELD_HISTORY:
		return setting{2, []string{"remember"}}
	case resourcev1.PasswordField_PASSWORD_FIELD_MAX_AGE:
		return setting{4, []string{"PASS_MAX_DAYS"}}
	case resourcev1.PasswordField_PASSWORD_FIELD_MIN_AGE:
		return setting{4, []string{"PASS_MIN_DAYS"}}
	case resourcev1.PasswordField_PASSWORD_FIELD_WARN:
		return setting{4, []string{"PASS_WARN_AGE"}}
	case resourcev1.PasswordField_PASSWORD_FIELD_FAILURE_LIMIT:
		return setting{3, []string{"deny", "local_users_only"}}
	case resourcev1.PasswordField_PASSWORD_FIELD_UNLOCK_AFTER:
		return setting{3, []string{"unlock_time", "local_users_only"}}
	case resourcev1.PasswordField_PASSWORD_FIELD_ENFORCE_ROOT:
		return setting{1, []string{"enforce_for_root", "local_users_only"}}
	default:
		return setting{}
	}
}
func filePath(kind agentv1.PasswordNativeFile) string {
	switch kind {
	case 1:
		return "/etc/security/pwquality.conf"
	case 2:
		return "/etc/security/pwhistory.conf"
	case 3:
		return "/etc/security/faillock.conf"
	case 4:
		return "/etc/login.defs"
	case 5:
		return "/usr/share/pam-configs/lindm-pwquality"
	case 6:
		return "/usr/share/pam-configs/lindm-pwhistory"
	case 7:
		return "/usr/share/pam-configs/lindm-faillock"
	case 8:
		return "/usr/share/pam-configs/lindm-faillock-pre"
	case 9:
		return "/etc/pam.d/system-auth"
	case 10:
		return "/etc/pam.d/lindm-password"
	case 11:
		return "/etc/pam.d/common-password-pc"
	default:
		return ""
	}
}
func fields(d *resourcev1.PasswordPolicyDesired) []resourcev1.PasswordField {
	var out []resourcev1.PasswordField
	if d == nil {
		return out
	}
	m := d.ProtoReflect()
	for n := protoreflect.FieldNumber(1); n <= 9; n++ {
		if m.Has(m.Descriptor().Fields().ByNumber(n)) {
			out = append(out, resourcev1.PasswordField(n))
		}
	}
	return out
}
func requested(d *resourcev1.PasswordPolicyDesired, field resourcev1.PasswordField) string {
	m := d.ProtoReflect()
	fd := m.Descriptor().Fields().ByNumber(protoreflect.FieldNumber(field))
	if fd.Kind() == protoreflect.BoolKind {
		if m.Get(fd).Bool() {
			return "1"
		}
		return "0"
	}
	return strconv.FormatUint(m.Get(fd).Uint(), 10)
}
func policySupported(d *resourcev1.PasswordPolicyDesired, product *resourcev1.PlatformProduct) error {
	// libpwquality has an effective native lower bound of six. Credits are disabled
	// when length is owned so min_length means actual characters, not score.
	if d.MinLength != nil && d.GetMinLength() < 6 {
		return fmt.Errorf("%w: libpwquality minimum length is six", ErrUnsupported)
	}
	// Shadow >= 4.20 tools fail while login.defs sets PASS_MIN_DAYS.
	if d.MinAgeDays != nil && platform.Of(product).Native().Quirks.NoPasswordMinAge {
		return fmt.Errorf("%w: shadow on this release has no minimum password age", ErrUnsupported)
	}
	return nil
}
func featureFor(field resourcev1.PasswordField) agentv1.PasswordNativeFeature {
	switch field {
	case 1, 2, 9:
		return 1
	case 3:
		return 2
	case 7, 8:
		return 3
	default:
		return 0
	}
}
func neededFeatures(d *resourcev1.PasswordPolicyDesired) []agentv1.PasswordNativeFeature {
	var out []agentv1.PasswordNativeFeature
	for _, f := range fields(d) {
		feature := featureFor(f)
		if feature != 0 && !slices.Contains(out, feature) {
			out = append(out, feature)
		}
	}
	slices.Sort(out)
	return out
}
func nativeFile(s *agentv1.ResourceOwnershipSnapshot, kind agentv1.PasswordNativeFile) *agentv1.PasswordNativeFileSnapshot {
	for _, f := range s.GetPasswordPolicy().GetFiles() {
		if f.GetKind() == kind {
			return f
		}
	}
	return nil
}
func settingsFor(field resourcev1.PasswordField) []setting {
	if field == 9 {
		return []setting{settingFor(field), {2, []string{"enforce_for_root"}}}
	}
	return []setting{settingFor(field)}
}
func assignment(line string, login bool) (string, string, bool, error) {
	if len(line) > 1023 || strings.ContainsRune(line, 0) {
		return "", "", false, ErrUnsupported
	}
	text := strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
	if text == "" {
		return "", "", false, nil
	}
	var key, value string
	if login {
		parts := strings.Fields(text)
		// shadow's getdef skips a name without a value ("only 1 field"); Arch's
		// shadow 4.20 login.defs ships a bare MOTD_FILE, which defines nothing.
		if len(parts) == 1 {
			return "", "", false, nil
		}
		if len(parts) != 2 {
			return "", "", false, ErrUnsupported
		}
		key, value = parts[0], parts[1]
	} else if before, after, ok := strings.Cut(text, "="); ok {
		key, value = strings.TrimSpace(before), strings.TrimSpace(after)
		if key == "" || value == "" || strings.ContainsAny(value, " \t\r\n") {
			return "", "", false, ErrUnsupported
		}
	} else {
		parts := strings.Fields(text)
		if len(parts) != 1 {
			return "", "", false, ErrUnsupported
		}
		key, value = parts[0], "1"
	}
	if !login && key != strings.ToLower(key) {
		return "", "", false, ErrUnsupported
	}
	return key, value, true, nil
}
func parseConfig(content []byte, login bool) (map[string]string, error) {
	values := make(map[string]string)
	for _, line := range strings.Split(string(content), "\n") {
		k, v, ok, err := assignment(line, login)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if _, exists := values[k]; exists {
			return nil, fmt.Errorf("%w: duplicate native setting %s", ErrUnsupported, k)
		}
		values[k] = v
	}
	return values, nil
}

// replaceKeys changes only selected directives, leaving other native text intact.
// A nil replacement restores absence; a baseline line preserves its exact bytes.
func replaceKeys(content []byte, keys []string, replacement []string, login bool) ([]byte, error) {
	lines := strings.SplitAfter(string(content), "\n")
	var result strings.Builder
	inserted := false
	for _, line := range lines {
		k, _, ok, err := assignment(line, login)
		if err != nil {
			return nil, err
		}
		if ok && slices.Contains(keys, k) {
			if !inserted {
				for _, r := range replacement {
					result.WriteString(r)
					if !strings.HasSuffix(r, "\n") {
						result.WriteByte('\n')
					}
				}
				inserted = true
			}
			continue
		}
		result.WriteString(line)
	}
	if !inserted && len(replacement) > 0 {
		if result.Len() > 0 && !strings.HasSuffix(result.String(), "\n") {
			result.WriteByte('\n')
		}
		for _, line := range replacement {
			result.WriteString(line)
			if !strings.HasSuffix(line, "\n") {
				result.WriteByte('\n')
			}
		}
	}
	return []byte(result.String()), nil
}
func selectedLines(content []byte, keys []string, login bool) ([]string, error) {
	var out []string
	for _, line := range strings.SplitAfter(string(content), "\n") {
		key, _, ok, err := assignment(line, login)
		if err != nil {
			return nil, err
		}
		if ok && slices.Contains(keys, key) {
			out = append(out, line)
		}
	}
	return out, nil
}
func setFileContent(f *agentv1.PasswordNativeFileSnapshot, content []byte) {
	f.Content = bytes.Clone(content)
	f.State.Exists = true
	if f.State.File == nil {
		f.State.File = &resourcev1.FileIdentity{Path: f.State.GetPath(), Mode: 0644}
	}
	digest := sha256.Sum256(content)
	f.State.File.Sha256 = digest[:]
}
func dimension(field resourcev1.PasswordField) agentv1.ResourceOwnedDimension {
	return agentv1.ResourceOwnedDimension(int32(field) + 39)
}
func dimensionFields(ds []agentv1.ResourceOwnedDimension) []resourcev1.PasswordField {
	var out []resourcev1.PasswordField
	for _, d := range ds {
		if d >= 40 && d <= 48 {
			out = append(out, resourcev1.PasswordField(int32(d)-39))
		}
	}
	return out
}
func sameSettings(a, b *agentv1.ResourceOwnershipSnapshot, fs []resourcev1.PasswordField) bool {
	if a.GetPasswordPolicy().GetManagerProfile() != b.GetPasswordPolicy().GetManagerProfile() {
		return false
	}
	for _, field := range fs {
		for _, spec := range settingsFor(field) {
			af, bf := nativeFile(a, spec.file), nativeFile(b, spec.file)
			if af == nil || bf == nil {
				return false
			}
			av, err := parseConfig(af.GetContent(), spec.file == 4)
			if err != nil {
				return false
			}
			bv, err := parseConfig(bf.GetContent(), spec.file == 4)
			if err != nil {
				return false
			}
			for _, key := range spec.keys {
				v, ok := av[key]
				w, exists := bv[key]
				if ok != exists || v != w {
					return false
				}
			}
		}
	}
	return true
}
func targetSnapshot(d *resourcev1.PasswordPolicyDesired, before *agentv1.ResourceOwnershipSnapshot, ledger *agentv1.ResourceOwnershipLedger, op resourcev1.ResourceOperation) (*agentv1.ResourceOwnershipSnapshot, error) {
	if before.GetPasswordPolicy() == nil {
		return nil, ErrUnsupported
	}
	target := proto.CloneOf(before)
	target.PasswordPolicy.AcquiredFeatures = append([]agentv1.PasswordNativeFeature(nil), ledger.GetLastApplied().GetPasswordPolicy().GetAcquiredFeatures()...)
	for _, feature := range target.PasswordPolicy.AcquiredFeatures {
		if !slices.Contains(before.GetPasswordPolicy().GetEnabledFeatures(), feature) {
			return nil, ErrConflict
		}
		for _, kind := range profileFiles(feature) {
			current := nativeFile(before, kind)
			if current == nil {
				continue
			}
			last := nativeFile(ledger.GetLastApplied(), kind)
			if last == nil || !bytes.Equal(current.GetContent(), last.GetContent()) || !proto.Equal(current.GetState().GetFile(), last.GetState().GetFile()) || !bytes.Equal(current.GetState().GetSecurityMetadataSha256(), last.GetState().GetSecurityMetadataSha256()) || !bytes.Equal(current.GetState().GetNativeIdentitySha256(), last.GetState().GetNativeIdentitySha256()) {
				return nil, ErrConflict
			}
		}
	}
	if op == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		if ledger.GetLastApplied() == nil {
			return nil, ErrConflict
		}
		if ledger.GetOwner().GetPolicy().GetRelease() == resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN {
			return target, nil
		}
		if ledger.GetOwner().GetPolicy().GetRelease() != resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED {
			return nil, ErrUnsupported
		}
		owned := dimensionFields(ledger.GetOwnedDimensions())
		if !sameSettings(before, ledger.GetLastApplied(), owned) {
			return nil, ErrConflict
		}
		for _, field := range owned {
			for _, spec := range settingsFor(field) {
				base := nativeFile(ledger.GetBaseline(), spec.file)
				current := nativeFile(target, spec.file)
				if base == nil || current == nil {
					return nil, ErrConflict
				}
				lines, err := selectedLines(base.GetContent(), spec.keys, spec.file == 4)
				if err != nil {
					return nil, err
				}
				content, err := replaceKeys(current.GetContent(), spec.keys, lines, spec.file == 4)
				if err != nil {
					return nil, err
				}
				setFileContent(current, content)
			}
		}
		for _, feature := range ledger.GetLastApplied().GetPasswordPolicy().GetAcquiredFeatures() {
			target.PasswordPolicy.EnabledFeatures = slices.DeleteFunc(target.PasswordPolicy.EnabledFeatures, func(f agentv1.PasswordNativeFeature) bool { return f == feature })
			for _, kind := range profileFiles(feature) {
				base, now := nativeFile(ledger.GetBaseline(), kind), nativeFile(target, kind)
				if now == nil {
					continue
				}
				if base == nil {
					return nil, ErrConflict
				}
				now.Content = bytes.Clone(base.GetContent())
				now.State = proto.CloneOf(base.GetState())
				now.Xattrs = base.GetXattrs()
			}
		}
		for kind := agentv1.PasswordNativeFile(1); kind <= 4; kind++ {
			base, last, current := nativeFile(ledger.GetBaseline(), kind), nativeFile(ledger.GetLastApplied(), kind), nativeFile(before, kind)
			if base == nil || last == nil || current == nil {
				return nil, ErrConflict
			}
			ownedFile := false
			for _, field := range owned {
				for _, spec := range settingsFor(field) {
					if spec.file == kind {
						ownedFile = true
						break
					}
				}
				if ownedFile {
					break
				}
			}
			file := nativeFile(target, kind)
			if ownedFile && !base.GetState().GetExists() && len(file.GetContent()) == 0 && bytes.Equal(current.GetContent(), last.GetContent()) && proto.Equal(current.GetState().GetFile(), last.GetState().GetFile()) && bytes.Equal(current.GetState().GetSecurityMetadataSha256(), last.GetState().GetSecurityMetadataSha256()) && bytes.Equal(current.GetState().GetNativeIdentitySha256(), last.GetState().GetNativeIdentitySha256()) {
				file.Content = nil
				file.State.Exists = false
				file.State.File = nil
				file.State.SecurityMetadataSha256 = bytes.Clone(base.GetState().GetSecurityMetadataSha256())
				file.Xattrs = nil
			}
		}
		target.PasswordPolicy.AcquiredFeatures = nil
		return target, nil
	}
	for _, field := range fields(d) {
		for _, spec := range settingsFor(field) {
			file := nativeFile(target, spec.file)
			if file == nil {
				return nil, ErrUnsupported
			}
			if ledger.GetLastApplied() != nil && !slices.Contains(ledger.GetOwnedDimensions(), dimension(field)) && !journal.PasswordBaselineDimensionMatches(ledger, before, dimension(field)) {
				return nil, ErrConflict
			}
			value := requested(d, field)
			separator := " = "
			if spec.file == 4 {
				separator = "\t"
			}
			replacement := []string{spec.keys[0] + separator + value}
			if field == 1 {
				for _, key := range spec.keys[1:] {
					if key != "local_users_only" {
						replacement = append(replacement, key+" = 0")
					}
				}
			}
			if field == 9 {
				replacement = nil
				if d.GetEnforceForRoot() {
					replacement = []string{"enforce_for_root"}
				}
			}
			if spec.file == 1 || spec.file == 3 {
				replacement = append(replacement, "local_users_only")
			}
			content, err := replaceKeys(file.GetContent(), spec.keys, replacement, spec.file == 4)
			if err != nil {
				return nil, err
			}
			setFileContent(file, content)
		}
	}
	for _, feature := range neededFeatures(d) {
		if slices.Contains(target.PasswordPolicy.EnabledFeatures, feature) {
			continue
		}
		target.PasswordPolicy.EnabledFeatures = append(target.PasswordPolicy.EnabledFeatures, feature)
		target.PasswordPolicy.AcquiredFeatures = append(target.PasswordPolicy.AcquiredFeatures, feature)
		for _, kind := range profileFiles(feature) {
			file := nativeFile(target, kind)
			if file == nil {
				continue
			}
			if file.GetState().GetExists() {
				return nil, ErrConflict
			}
			setFileContent(file, []byte(profileText(kind)))
		}
	}
	slices.Sort(target.PasswordPolicy.EnabledFeatures)
	slices.Sort(target.PasswordPolicy.AcquiredFeatures)
	return target, nil
}
func profileFiles(feature agentv1.PasswordNativeFeature) []agentv1.PasswordNativeFile {
	switch feature {
	case 1:
		return []agentv1.PasswordNativeFile{5}
	case 2:
		return []agentv1.PasswordNativeFile{6}
	case 3:
		return []agentv1.PasswordNativeFile{7, 8}
	default:
		return nil
	}
}
func profileText(kind agentv1.PasswordNativeFile) string {
	switch kind {
	case 5:
		return "Name: Lindm local password quality\nDefault: no\nPriority: 1024\nPassword-Type: Primary\nPassword:\n requisite pam_pwquality.so retry=3 local_users_only\nPassword-Initial:\n requisite pam_pwquality.so retry=3 local_users_only\n"
	case 6:
		return "Name: Lindm local password history\nDefault: no\nPriority: 1023\nPassword-Type: Primary\nPassword:\n [default=1 ignore=ignore success=ok] pam_localuser.so\n required pam_pwhistory.so use_authtok\nPassword-Initial:\n [default=1 ignore=ignore success=ok] pam_localuser.so\n required pam_pwhistory.so\n"
	case 7:
		return "Name: Lindm local authentication failure counting\nDefault: no\nPriority: 0\nAuth-Type: Primary\nAuth:\n [default=die] pam_faillock.so authfail\n"
	case 8:
		return "Name: Lindm local authentication lockout check\nDefault: no\nPriority: 1024\nAuth-Type: Primary\nAuth:\n requisite pam_faillock.so preauth\nAccount-Type: Primary\nAccount:\n required pam_faillock.so\n"
	default:
		return ""
	}
}
