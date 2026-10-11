//go:build linux

package vmlab

import (
	"strconv"
	"strings"
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// The secret-password kind installs the host fixture too, and the account
// provider refuses to create a user whose UID another local account holds.
// Every account the lanes create through the provider must therefore be free
// of the fixture's native useradd UIDs and inside the root-approved range.
func TestProviderCreatedLabAccountsAvoidFixtureUIDs(t *testing.T) {
	held := make(map[uint64]string)
	for line := range strings.SplitSeq(resourceHostFixtureScript, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "useradd" {
			continue
		}
		for i := 1; i+1 < len(fields); i++ {
			if fields[i] == "-u" {
				uid, err := strconv.ParseUint(fields[i+1], 10, 32)
				if err != nil {
					t.Fatalf("fixture useradd UID %q: %v", fields[i+1], err)
				}
				held[uid] = fields[len(fields)-1]
			}
		}
	}
	if len(held) == 0 {
		t.Fatal("host fixture creates no native accounts")
	}
	config := new(agentv1.AgentConfig)
	provisionHostResourceRoots(config)
	approved := config.GetAccountProvider()
	for name, uid := range map[string]uint64{resourceSecretUser: resourceSecretUserID, resourceLabUser: resourceLabUserID, resourceLabReuse: resourceLabReuseID} {
		if owner, ok := held[uid]; ok {
			t.Errorf("%s UID %d is already held by fixture account %s", name, uid, owner)
		}
		if uid < uint64(approved.GetMinUid()) || uid > uint64(approved.GetMaxUid()) {
			t.Errorf("%s UID %d outside the approved range %d-%d", name, uid, approved.GetMinUid(), approved.GetMaxUid())
		}
	}
}
