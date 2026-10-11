//go:build linux

package passwordprovider

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

const nativePasswordInclude = "password include lindm-password\n"
const nativeTokenSuffix = " use_authtok # lindm-password token\n"

// splitNativePAM recognizes exactly our include. Other includes in system-auth
// are not flattened speculatively: their controls can bypass local policy.
func splitNativePAM(stack []byte) ([]byte, bool, error) {
	var base bytes.Buffer
	included, passwordSeen := false, false
	for _, line := range strings.SplitAfter(string(stack), "\n") {
		if strings.HasSuffix(line, nativeTokenSuffix) {
			original := strings.TrimSuffix(line, nativeTokenSuffix)
			fields := strings.Fields(original)
			if !included || len(fields) < 3 || fields[0] != "password" || fields[1] != "required" || fields[2] != "pam_unix.so" || strings.Contains(original, "#") || slices.Contains(fields, "use_authtok") {
				return nil, false, ErrUnsupported
			}
			line = original + "\n"
		}
		fields := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(fields) == 0 {
			base.WriteString(line)
			continue
		}
		if line == nativePasswordInclude {
			if included || passwordSeen {
				return nil, false, ErrUnsupported
			}
			included = true
			continue
		}
		if strings.Contains(line, "lindm-password") {
			return nil, false, ErrUnsupported
		}
		if strings.TrimPrefix(fields[0], "-") == "password" {
			passwordSeen = true
		}
		base.WriteString(line)
	}
	if !passwordSeen {
		return nil, false, ErrUnsupported
	}
	return base.Bytes(), included, nil
}

func insertNativeInclude(base []byte, tokenProduced bool) ([]byte, error) {
	var out strings.Builder
	included, unix := false, false
	for _, line := range strings.SplitAfter(string(base), "\n") {
		fields := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(fields) > 0 && strings.TrimPrefix(fields[0], "-") == "password" && !included {
			out.WriteString(nativePasswordInclude)
			included = true
		}
		if len(fields) >= 3 && fields[0] == "password" && fields[2] == "pam_unix.so" {
			if unix || fields[1] != "required" {
				return nil, ErrUnsupported
			}
			unix = true
			if tokenProduced && !slices.Contains(fields, "use_authtok") {
				if strings.Contains(line, "#") || !strings.HasSuffix(line, "\n") {
					return nil, ErrUnsupported
				}
				line = strings.TrimSuffix(line, "\n") + nativeTokenSuffix
			}
		}
		out.WriteString(line)
	}
	if !included || !unix {
		return nil, ErrUnsupported
	}
	return []byte(out.String()), nil
}

func nativePolicy(features []agentv1.PasswordNativeFeature) []byte {
	var out strings.Builder
	if slices.Contains(features, 1) {
		out.WriteString("password requisite pam_pwquality.so retry=3 local_users_only\n")
	}
	if slices.Contains(features, 2) {
		out.WriteString("password [default=1 ignore=ignore success=ok] pam_localuser.so\npassword required pam_pwhistory.so")
		if slices.Contains(features, 1) {
			out.WriteString(" use_authtok")
		}
		out.WriteByte('\n')
	}
	return []byte(out.String())
}

func inspectNativePAM() (*managerState, error) {
	stack, err := readNative(filePath(9), 32768)
	if err != nil {
		return nil, err
	}
	policy, err := readNative(filePath(10), 32768)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	policyExists := err == nil
	history, err := readNative(filePath(2), 32768)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return nativePAMState(stack, policy, policyExists, history)
}

func nativePAMState(stack, policy []byte, policyExists bool, history []byte) (*managerState, error) {
	base, included, err := splitNativePAM(stack)
	if err != nil {
		return nil, err
	}
	baseFeatures, err := inspectStacks(map[string][]byte{"system-auth": base})
	if err != nil {
		return nil, err
	}
	if included != policyExists {
		return nil, fmt.Errorf("%w: native PAM include has no owned policy", ErrUnsupported)
	}
	expanded := stack
	if included {
		if slices.Contains(baseFeatures, 1) || slices.Contains(baseFeatures, 2) {
			return nil, fmt.Errorf("%w: mixed owned and native password modules", ErrUnsupported)
		}
		features, err := inspectStacks(map[string][]byte{"lindm-password": policy})
		if err != nil || len(features) == 0 || !bytes.Equal(policy, nativePolicy(features)) {
			return nil, fmt.Errorf("%w: foreign native PAM policy", ErrUnsupported)
		}
		produces, err := nativeTokenProduced(features, history)
		if err != nil {
			return nil, err
		}
		expected, err := insertNativeInclude(base, produces)
		if err != nil || !bytes.Equal(expected, stack) {
			return nil, fmt.Errorf("%w: native password token flow changed", ErrUnsupported)
		}
		expanded = bytes.Replace(stack, []byte(nativePasswordInclude), policy, 1)
	}
	features, err := inspectStacks(map[string][]byte{"system-auth": expanded})
	if err != nil {
		return nil, err
	}
	graph, profile := sha256.New(), sha256.New()
	hashRecord(graph, "system-auth", stack, true)
	hashRecord(graph, "lindm-password", policy, policyExists)
	hashRecord(profile, "system-auth", base, true)
	return &managerState{profile: "native-pam", features: features, stacks: map[string][]byte{"system-auth": expanded}, generation: graph.Sum(nil), profileDigest: profile.Sum(nil)}, nil
}

func nativePAMChangeSupported(before, target *agentv1.ResourceOwnershipSnapshot) error {
	// Arch's vendor faillock flow is retained, never manufactured or removed.
	if slices.Contains(before.GetPasswordPolicy().GetEnabledFeatures(), 3) != slices.Contains(target.GetPasswordPolicy().GetEnabledFeatures(), 3) {
		return fmt.Errorf("%w: native faillock flow must already be configured", ErrUnsupported)
	}
	return nil
}

func nativeTokenProduced(features []agentv1.PasswordNativeFeature, history []byte) (bool, error) {
	if slices.Contains(features, 1) {
		return true, nil
	}
	if !slices.Contains(features, 2) {
		return false, nil
	}
	settings, err := parseConfig(history, false)
	if err != nil {
		return false, err
	}
	// pam_pwhistory returns PAM_IGNORE without obtaining PAM_AUTHTOK when
	// remember=0. Absence retains Linux-PAM's nonzero default.
	value, ok := settings["remember"]
	if !ok {
		return true, nil
	}
	remember, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return false, ErrUnsupported
	}
	return remember != 0, nil
}

func targetNativePAM(before, target *agentv1.ResourceOwnershipSnapshot, ledger *agentv1.ResourceOwnershipLedger) error {
	stack, policy := nativeFile(before, 9), nativeFile(before, 10)
	if stack == nil || policy == nil || !stack.GetState().GetExists() {
		return ErrUnsupported
	}
	base, included, err := splitNativePAM(stack.GetContent())
	if err != nil {
		return err
	}
	if included {
		last := nativeFile(ledger.GetLastApplied(), 10)
		if last == nil || !bytes.Equal(last.GetContent(), policy.GetContent()) || !proto.Equal(last.GetState().GetFile(), policy.GetState().GetFile()) {
			return ErrConflict
		}
	}
	// Only features acquired by this ledger belong in our include. Native
	// modules already present in system-auth remain the administrator's.
	content := nativePolicy(target.GetPasswordPolicy().GetAcquiredFeatures())
	if len(content) > 0 {
		if !included && policy.GetState().GetExists() {
			return ErrConflict
		}
		features, err := inspectStacks(map[string][]byte{"system-auth": base})
		if err != nil {
			return err
		}
		if slices.Contains(features, 1) || slices.Contains(features, 2) {
			return fmt.Errorf("%w: mixed owned and native password modules", ErrUnsupported)
		}
		produces, err := nativeTokenProduced(target.GetPasswordPolicy().GetAcquiredFeatures(), nativeFile(target, 2).GetContent())
		if err != nil {
			return err
		}
		withInclude, err := insertNativeInclude(base, produces)
		if err != nil {
			return err
		}
		setFileContent(nativeFile(target, 9), withInclude)
		setFileContent(nativeFile(target, 10), content)
	} else if included {
		setFileContent(nativeFile(target, 9), base)
		baseline := nativeFile(ledger.GetBaseline(), 10)
		if baseline == nil || baseline.GetState().GetExists() {
			return ErrConflict
		}
		file := nativeFile(target, 10)
		file.Content = nil
		file.State = proto.CloneOf(baseline.GetState())
		file.Xattrs = baseline.GetXattrs()
	}
	state, err := nativePAMState(nativeFile(target, 9).GetContent(), nativeFile(target, 10).GetContent(), nativeFile(target, 10).GetState().GetExists(), nativeFile(target, 2).GetContent())
	if err != nil {
		return err
	}
	if !slices.Equal(state.features, target.GetPasswordPolicy().GetEnabledFeatures()) {
		return ErrUnsupported
	}
	return nativePAMChangeSupported(before, target)
}
