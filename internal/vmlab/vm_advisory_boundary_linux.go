//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"lindm/internal/advisory"
	"lindm/internal/advisory/feed"
	"lindm/internal/devlab"
)

// VMAdvisoryBoundaryEvidence is explicitly a version-only comparison oracle,
// not an inventory modification or an installed vulnerable-package assertion.
type VMAdvisoryBoundaryEvidence struct {
	Scope             string                            `json:"scope"`
	Input             *devlab.PublishedAdvisoryBoundary `json:"input"`
	Manager           string                            `json:"manager"`
	NativeComparisons [3]int                            `json:"native_comparisons"`
	ServerComparisons [3]int                            `json:"server_comparisons"`
	VulnerableMatched bool                              `json:"vulnerable_matched"`
	FixedMatched      bool                              `json:"fixed_matched"`
}

func exerciseVMAdvisoryBoundary(ctx context.Context, vm *guestVM, fixture *devlab.AuthorityFixture, e *VMAdvisoryEvidence, manager string) (*VMAdvisoryBoundaryEvidence, error) {
	input, err := fixture.ReadPublishedAdvisoryBoundary(ctx, e.Source.GetId(), e.Feed.GetSourceSha256(), manager)
	if err != nil {
		return nil, err
	}
	result := &VMAdvisoryBoundaryEvidence{Scope: "real vendor version boundaries; comparison inputs are not installed-package exposure", Input: input, Manager: manager}
	low, fixed := input.VulnerableVersion, input.Claim.GetFixedVersion()
	for i, pair := range [][2]string{{low, fixed}, {fixed, fixed}, {fixed, low}} {
		command, err := vmAdvisoryCompareCommand(manager, pair[0], pair[1])
		if err != nil {
			return result, err
		}
		output, err := vm.run(ctx, "env -i PATH=/usr/bin:/bin HOME=/ LANG=C LC_ALL=C "+command, nil, 1024, 15*time.Second)
		if err != nil {
			return result, fmt.Errorf("native advisory version oracle: %w", err)
		}
		value, err := strconv.Atoi(strings.TrimSpace(string(output)))
		if err != nil || value < -1 || value > 1 {
			return result, errors.New("native advisory comparator returned invalid output")
		}
		result.NativeComparisons[i] = value
		result.ServerComparisons[i], err = feed.Compare(manager, pair[0], pair[1])
		if err != nil {
			return result, err
		}
	}
	result.VulnerableMatched, err = advisory.MatchesVersion(manager, low, input.Claim)
	if err != nil {
		return result, err
	}
	result.FixedMatched, err = advisory.MatchesVersion(manager, fixed, input.Claim)
	if err != nil {
		return result, err
	}
	if !validVMAdvisoryBoundary(result) {
		return result, errors.New("native vendor boundary oracle disagrees with server version matching")
	}
	return result, nil
}

func validVMAdvisoryBoundary(e *VMAdvisoryBoundaryEvidence) bool {
	return e != nil && e.Input != nil && e.Input.Claim != nil && e.Input.VulnerableVersion != "" && e.NativeComparisons == [3]int{-1, 0, 1} && e.ServerComparisons == e.NativeComparisons && e.VulnerableMatched && !e.FixedMatched
}

func vmAdvisoryCompareCommand(manager, a, b string) (string, error) {
	switch manager {
	case "pacman":
		return "vercmp " + nativeQuote(a) + " " + nativeQuote(b), nil
	case "rpm":
		// rpm.ver compares full epoch/version/release objects (RPM >=4.16).
		// Vendor strings become numeric Lua byte literals: neither shell quoting,
		// Lua quoting nor RPM macro expansion can interpret vendor input as code.
		lua := "%{lua:local a=rpm.ver(" + advisoryLuaBytes(a) + ");local b=rpm.ver(" + advisoryLuaBytes(b) + ");if a < b then print(-1) elseif a == b then print(0) else print(1) end}"
		return "rpm --eval " + nativeQuote(lua), nil
	case "dpkg":
		// dpkg reports ordering only through exit status; vendor strings stay
		// positional parameters, and a version dpkg cannot order exits 2.
		script := `if dpkg --compare-versions "$1" lt "$2"; then echo -1; elif dpkg --compare-versions "$1" eq "$2"; then echo 0; elif dpkg --compare-versions "$1" gt "$2"; then echo 1; else exit 2; fi`
		return "sh -c " + nativeQuote(script) + " sh " + nativeQuote(a) + " " + nativeQuote(b), nil
	default:
		return "", errors.New("advisory boundary oracle requires native pacman, RPM or dpkg")
	}
}

func advisoryLuaBytes(value string) string {
	var out strings.Builder
	out.WriteString("string.char(")
	for i := range len(value) {
		if i != 0 {
			out.WriteByte(',')
		}
		out.WriteString(strconv.Itoa(int(value[i])))
	}
	out.WriteByte(')')
	return out.String()
}
