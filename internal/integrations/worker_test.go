package integrations

import (
	"testing"
	"time"
)

func TestRetryDelayBoundedExponentialJitter(t *testing.T) {
	for attempt := int32(1); attempt <= 10; attempt++ {
		ceiling := 5 * time.Second * time.Duration(1<<uint(attempt-1))
		if ceiling > 15*time.Minute {
			ceiling = 15 * time.Minute
		}
		distinct := make(map[time.Duration]bool)
		for range 64 {
			delay := retryDelay(attempt)
			if delay < ceiling/2 || delay > ceiling {
				t.Fatalf("attempt %d delay %s outside [%s,%s]", attempt, delay, ceiling/2, ceiling)
			}
			distinct[delay] = true
		}
		if len(distinct) < 2 {
			t.Fatalf("attempt %d lacks jitter", attempt)
		}
	}
}
