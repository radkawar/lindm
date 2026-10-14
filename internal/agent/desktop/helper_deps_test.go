// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"reflect"
	"testing"
	"time"
)

// Every production session interval must be set: a zero recording flush
// panicked the helper's recorder ticker at the start of each recorded session
// (layers-fedora44-tier2-05). The harness overrides some of these; the
// production values are read before it does.
func TestProductionSessionDurationsAreSet(t *testing.T) {
	h := newHarness(t)
	h.helper.deps.repostInterval, h.helper.deps.captureGrace = 2*time.Second, time.Second
	deps := reflect.ValueOf(h.helper.deps).Elem()
	for i := range deps.NumField() {
		field := deps.Type().Field(i)
		if field.Type == reflect.TypeFor[time.Duration]() && deps.Field(i).Int() <= 0 {
			t.Errorf("session dependency %s is not set", field.Name)
		}
	}
}
