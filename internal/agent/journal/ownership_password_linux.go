//go:build linux

package journal

import (
	"bytes"
	"crypto/sha256"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func passwordOwnershipSnapshotValid(snapshot *agentv1.ResourceOwnershipSnapshot) bool {
	observation, private := snapshot.GetObservation().GetPasswordPolicy(), snapshot.GetPasswordPolicy()
	if observation == nil {
		return private == nil
	}
	if private == nil || private.GetManagerProfile() != observation.GetPamOwner() || len(private.GetManagerGenerationSha256()) != 32 || len(private.GetManagerProfileSha256()) != 32 || len(private.GetQualityDropinsSha256()) != 32 {
		return false
	}
	files := private.GetFiles()
	if len(files) != 4 && len(files) != 5 && len(files) != 6 && len(files) != 8 {
		return false
	}
	for i, file := range files {
		expected := i + 1
		if len(files) == 6 && i >= 4 {
			expected = i + 5
		}
		if len(files) == 5 && i == 4 {
			expected = 11
		}
		if int(file.GetKind()) != expected || len(file.GetNativeRevisionSha256()) != 32 {
			return false
		}
		var path string
		switch file.GetKind() {
		case 1:
			path = "/etc/security/pwquality.conf"
		case 2:
			path = "/etc/security/pwhistory.conf"
		case 3:
			path = "/etc/security/faillock.conf"
		case 4:
			path = "/etc/login.defs"
		case 5:
			path = "/usr/share/pam-configs/lindm-pwquality"
		case 6:
			path = "/usr/share/pam-configs/lindm-pwhistory"
		case 7:
			path = "/usr/share/pam-configs/lindm-faillock"
		case 8:
			path = "/usr/share/pam-configs/lindm-faillock-pre"
		case 9:
			path = "/etc/pam.d/system-auth"
		case 10:
			path = "/etc/pam.d/lindm-password"
		case 11:
			path = "/etc/pam.d/common-password-pc"
		default:
			return false
		}
		state := file.GetState()
		if state == nil || state.GetPath() != path || state.GetExists() != (file.Content != nil) || state.GetExists() != (state.GetFile() != nil) || len(state.GetAncestrySha256()) != 32 || len(state.GetNativeIdentitySha256()) != 32 || len(state.GetSecurityMetadataSha256()) != 32 {
			return false
		}
		if state.GetExists() {
			digest := sha256.Sum256(file.GetContent())
			if state.GetFile().GetPath() != path || !bytes.Equal(digest[:], state.GetFile().GetSha256()) || state.GetFile().GetUid() != 0 || state.GetFile().GetMode()&0022 != 0 {
				return false
			}
		}
	}
	return true
}
func passwordOwnershipDimensionKind(kind resourcev1.ResourceKind, dimension agentv1.ResourceOwnedDimension) bool {
	return kind == resourcev1.ResourceKind_RESOURCE_KIND_PASSWORD_POLICY && dimension >= 40 && dimension <= 49
}
func passwordOwnershipDimensionAllowed(action *agentv1.ResourceExecutionRecord, dimension agentv1.ResourceOwnedDimension) bool {
	d := action.GetNativePlan().GetPasswordPolicy().GetDesired()
	if d == nil || dimension < 40 || dimension > 49 {
		return false
	}
	if dimension == 49 {
		return true
	}
	m := d.ProtoReflect()
	return m.Has(m.Descriptor().Fields().ByNumber(protoreflect.FieldNumber(dimension - 39)))
}
func passwordOwnershipDimensionMatches(left, right *agentv1.ResourceOwnershipSnapshot, dimension agentv1.ResourceOwnedDimension) bool {
	a, b := left.GetObservation().GetPasswordPolicy(), right.GetObservation().GetPasswordPolicy()
	if a == nil || b == nil || a.GetPamOwner() != b.GetPamOwner() || left.GetPasswordPolicy().GetManagerProfile() != right.GetPasswordPolicy().GetManagerProfile() {
		return false
	}
	if dimension == 49 {
		return true
	} // Individual manager feature inverses are checked by the provider; unrelated features are retained.
	if dimension < 40 || dimension > 48 {
		return false
	}
	am, bm := a.GetEffective().ProtoReflect(), b.GetEffective().ProtoReflect()
	field := am.Descriptor().Fields().ByNumber(protoreflect.FieldNumber(dimension - 39))
	return am.Has(field) == bm.Has(field) && (!am.Has(field) || am.Get(field).Interface() == bm.Get(field).Interface())
}
func passwordOwnershipAcquisitionAllowed(intent *agentv1.ResourceExecutionIntent, snapshot *agentv1.ResourceOwnershipSnapshot) bool {
	return passwordOwnershipSnapshotValid(snapshot) && snapshot.GetObservation().GetPasswordPolicy() != nil && intent.GetOwnership().GetPolicy().GetMode() == resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION && intent.GetOwnership().GetPolicy().GetAdoptionApprovalId() != ""
}

// PasswordOwnershipMatches compares only signed policy dimensions, not accounts,
// unrelated login defaults, entire PAM stacks or other manager features.
func PasswordOwnershipMatches(left, right *agentv1.ResourceOwnershipSnapshot, dimensions []agentv1.ResourceOwnedDimension) bool {
	if left == nil || right == nil || len(dimensions) == 0 {
		return false
	}
	for _, dimension := range dimensions {
		if !passwordOwnershipDimensionMatches(left, right, dimension) {
			return false
		}
	}
	return true
}

type passwordNativeKey struct {
	file agentv1.PasswordNativeFile
	name string
}

// Compound native keys are shared across signed dimensions. Their baseline
// belongs to the first acquisition, rather than the currently enabled module.
var passwordDimensionKeys = [9][]passwordNativeKey{
	{{1, "minlen"}, {1, "dcredit"}, {1, "ucredit"}, {1, "lcredit"}, {1, "ocredit"}, {1, "local_users_only"}},
	{{1, "minclass"}, {1, "local_users_only"}},
	{{2, "remember"}},
	{{4, "PASS_MAX_DAYS"}},
	{{4, "PASS_MIN_DAYS"}},
	{{4, "PASS_WARN_AGE"}},
	{{3, "deny"}, {3, "local_users_only"}},
	{{3, "unlock_time"}, {3, "local_users_only"}},
	{{1, "enforce_for_root"}, {1, "local_users_only"}, {2, "enforce_for_root"}},
}

func passwordNativeDirectives(snapshot *agentv1.ResourceOwnershipSnapshot, kind agentv1.PasswordNativeFile) (map[string]string, bool) {
	var content []byte
	found := false
	for _, file := range snapshot.GetPasswordPolicy().GetFiles() {
		if file.GetKind() == kind {
			content = file.GetContent()
			found = true
			break
		}
	}
	if !found {
		return nil, false
	}
	values := make(map[string]string)
	for _, line := range strings.Split(string(content), "\n") {
		line, _, _ = strings.Cut(line, "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value := "", ""
		if kind == 4 {
			parts := strings.Fields(line)
			if len(parts) != 2 {
				return nil, false
			}
			key, value = parts[0], parts[1]
		} else {
			var equals bool
			key, value, equals = strings.Cut(line, "=")
			key, value = strings.TrimSpace(key), strings.TrimSpace(value)
			if !equals {
				value = "1"
			}
		}
		if _, duplicate := values[key]; duplicate {
			return nil, false
		}
		values[key] = value
	}
	return values, true
}

// PasswordBaselineDimensionMatches permits adding a setting after this ledger
// enabled its PAM module. Native defaults becoming observable is not drift.
// Only raw keys already owned by another signed dimension may differ from the
// original baseline; all newly acquired keys retain their original baseline.
func PasswordBaselineDimensionMatches(ledger *agentv1.ResourceOwnershipLedger, current *agentv1.ResourceOwnershipSnapshot, dimension agentv1.ResourceOwnedDimension) bool {
	baseline := ledger.GetBaseline()
	if baseline.GetPasswordPolicy() == nil || current.GetPasswordPolicy() == nil || baseline.GetPasswordPolicy().GetManagerProfile() != current.GetPasswordPolicy().GetManagerProfile() {
		return false
	}
	if dimension == 49 {
		return true
	}
	if dimension < 40 || dimension > 48 {
		return false
	}
	if (dimension == 40 || dimension == 41 || dimension == 48) && !bytes.Equal(baseline.GetPasswordPolicy().GetQualityDropinsSha256(), current.GetPasswordPolicy().GetQualityDropinsSha256()) {
		return false
	}
	var baseMaps, currentMaps [4]map[string]string
	for _, key := range passwordDimensionKeys[dimension-40] {
		previouslyOwned := false
		for _, owned := range ledger.GetOwnedDimensions() {
			if owned < 40 || owned > 48 || owned == dimension {
				continue
			}
			for _, other := range passwordDimensionKeys[owned-40] {
				if key == other {
					previouslyOwned = true
					break
				}
			}
			if previouslyOwned {
				break
			}
		}
		if previouslyOwned {
			continue
		}
		index := int(key.file) - 1
		if baseMaps[index] == nil {
			var ok bool
			baseMaps[index], ok = passwordNativeDirectives(baseline, key.file)
			if !ok {
				return false
			}
			currentMaps[index], ok = passwordNativeDirectives(current, key.file)
			if !ok {
				return false
			}
		}
		before, beforePresent := baseMaps[index][key.name]
		now, nowPresent := currentMaps[index][key.name]
		if beforePresent != nowPresent || before != now {
			return false
		}
	}
	return true
}
