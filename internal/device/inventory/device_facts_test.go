// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"strings"
	"testing"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
)

func TestAgentVersionSchemaBounds(t *testing.T) {
	for _, test := range []struct {
		name    string
		message proto.Message
		valid   bool
	}{
		{"unreported", &adminv1.Device{}, true},
		{"reported", &adminv1.Device{AgentRelease: "1.3.7", AgentProtocolVersion: 1}, true},
		{"release limit", &adminv1.Device{AgentRelease: strings.Repeat("a", 128)}, true},
		{"release oversized", &adminv1.Device{AgentRelease: strings.Repeat("a", 129)}, false},
		{"protocol oversized", &adminv1.Device{AgentProtocolVersion: 1 << 31}, false},
		{"empty filter", &adminv1.DeviceFilter{}, true},
		{"exact filter", &adminv1.DeviceFilter{AgentRelease: "1.3.7"}, true},
		{"oversized filter", &adminv1.DeviceFilter{AgentRelease: strings.Repeat("a", 129)}, false},
		{"nul filter", &adminv1.DeviceFilter{AgentRelease: "1.3\x00"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := protovalidate.Validate(test.message); (err == nil) != test.valid {
				t.Fatalf("schema valid=%v, error=%v", test.valid, err)
			}
		})
	}
}
