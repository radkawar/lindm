// SPDX-License-Identifier: Apache-2.0

package loadlab

import (
	"math/rand/v2"
	"testing"
	"time"
)

func TestJitterPreservesCadenceAndSeed(t *testing.T) {
	first := rand.New(rand.NewPCG(71, 9))
	same := rand.New(rand.NewPCG(71, 9))
	var total time.Duration
	for range 10000 {
		delay := jitter(first, time.Minute)
		if delay < 54*time.Second || delay >= 66*time.Second {
			t.Fatalf("heartbeat outside agent jitter bounds: %s", delay)
		}
		if delay != jitter(same, time.Minute) {
			t.Fatal("recorded seed cannot reproduce schedule")
		}
		total += delay
	}
	mean := total / 10000
	if mean < 59500*time.Millisecond || mean > 60500*time.Millisecond {
		t.Fatalf("jitter changes offered heartbeat rate: mean %s", mean)
	}
}
