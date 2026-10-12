package dispatch

import (
	"os"
	"regexp"
	"testing"
)

// Every precondition reason CreateDeviceAction and PreflightDeviceAction can
// return must have plain copy in the console, never "Something went wrong".
func TestDeviceActionReasonsHaveConsoleCopy(t *testing.T) {
	sources := []string{
		"device_action_admin.go",
		"device_action_preflight.go",
		"device_action_wipe.go",
		"device_actions.go",
		"../core/action_rules.go",
		"../core/authorization.go",
		"../inventory/recovery_readiness.go",
	}
	literal := regexp.MustCompile(`CodeFailedPrecondition, "([a-z0-9_]+)"`)
	readiness := regexp.MustCompile(`"(device_action_(?:recovery_[a-z0-9_]+|esp_insufficient))"`)
	reasons := map[string]bool{}
	for _, source := range sources {
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range literal.FindAllSubmatch(data, -1) {
			reasons[string(match[1])] = true
		}
		for _, match := range readiness.FindAllSubmatch(data, -1) {
			reasons[string(match[1])] = true
		}
	}
	if len(reasons) < 20 {
		t.Fatalf("found only %d reasons; the source list is stale", len(reasons))
	}
	copyTable, err := os.ReadFile("../../../web/src/lib/errors.ts")
	if err != nil {
		t.Fatal(err)
	}
	for reason := range reasons {
		if !regexp.MustCompile(`case "` + reason + `":`).Match(copyTable) {
			t.Errorf("device action reason %q has no console copy in web/src/lib/errors.ts classifyRpcFailure", reason)
		}
	}
}
