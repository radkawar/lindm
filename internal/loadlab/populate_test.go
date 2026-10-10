package loadlab

import (
	"context"
	"errors"
	"testing"

	"lindm/internal/devlab"
)

func TestPopulateRequiresLiveOwnedFixture(t *testing.T) {
	options := PopulateOptions{Devices: 3, Packages: 8, AssignmentPercent: 100, EnrollmentWorkers: 2}
	for _, fixture := range []*devlab.AuthorityFixture{nil, {AdminAddress: "127.0.0.1:18444", DeviceAddress: "127.0.0.1:18445"}} {
		if _, err := Populate(t.Context(), fixture, options); err == nil {
			t.Fatal("population accepted addresses without a live owned fixture")
		}
	}
}

func TestPopulateCanceledBeforeAcquiringResources(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := Populate(ctx, nil, PopulateOptions{Devices: 3, Packages: 8, AssignmentPercent: 100, EnrollmentWorkers: 2})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled population: %v", err)
	}
}
