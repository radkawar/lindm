package loadlab

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/devlab"
)

// PopulateOptions selects the bounded synthetic workload used by console QA.
// These are simulated observations, not evidence of native device behavior.
type PopulateOptions struct {
	Devices           int
	Packages          int
	AssignmentPercent int
	EnrollmentWorkers int
	// HostObservationFile replays a captured host report for the first device.
	// Its original fields/timestamps are retained and metadata labels the replay.
	HostObservationFile string
}

// Population contains no credentials and may be printed as fixture evidence.
type Population struct {
	DeviceIDs            []string
	CompletedAssignments uint64
	HistoricalDeviceID   string
}

// Populate runs the capacity generator against a caller-owned isolated fixture.
// It never accepts endpoints or production credentials, closes the fixture, or
// leaves background device work running. All temporary device keys, transports
// and its owner session are released before return, including on cancellation.
// The caller must not concurrently close or reconfigure the fixture.
func Populate(ctx context.Context, fixture *devlab.AuthorityFixture, options PopulateOptions) (result Population, resultErr error) {
	if options.Devices < 1 || options.Devices > 10000 || options.Packages < 1 || options.Packages > 5000 || options.AssignmentPercent < 1 || options.AssignmentPercent > 100 || options.EnrollmentWorkers < 1 || options.EnrollmentWorkers > 64 {
		return result, errors.New("load: invalid bounded population options")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	var historical *inventoryv1.HostObservation
	if options.HostObservationFile != "" {
		var err error
		historical, err = readHistoricalHost(options.HostObservationFile)
		if err != nil {
			return result, err
		}
	}
	r := &runner{fixture: fixture, metrics: &measurements{}, historicalHost: historical, options: Options{Packages: options.Packages, AssignmentPercent: options.AssignmentPercent, EnrollmentWorkers: options.EnrollmentWorkers}}
	if err := r.prepare(ctx); err != nil {
		return result, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		resultErr = errors.Join(resultErr, r.owner.Close(cleanup))
	}()
	defer r.enrollmentTransport.CloseIdleConnections()
	devices, err := r.enrollBatch(ctx, 0, options.Devices)
	defer func() {
		for _, device := range devices {
			device.close()
		}
	}()
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if err != nil {
		return result, fmt.Errorf("populate console devices: %w", err)
	}
	if historical != nil {
		device := devices[0]
		_, err := r.owner.Admin.SetDeviceMetadata(ctx, connect.NewRequest(&adminv1.SetDeviceMetadataRequest{
			RequestId: uuid.NewString(), DeviceId: device.id,
			Metadata: &adminv1.DeviceMetadata{
				Labels: []string{"historical-inventory-replay"},
				Owner:  &adminv1.DeviceMetadata_OwnerText{OwnerText: "Historical inventory replay, not a live device"},
			},
			Reason: "Label captured historical host observation replay in isolated console fixture",
		}))
		if err != nil {
			return result, fmt.Errorf("label historical inventory replay: %w", err)
		}
		result.HistoricalDeviceID = device.id
	}
	result.DeviceIDs = make([]string, 0, len(devices))
	for index, device := range devices {
		result.DeviceIDs = append(result.DeviceIDs, device.id)
		if index%100 >= options.AssignmentPercent {
			continue
		}
		if err := r.completePopulationAssignment(ctx, device); err != nil {
			return result, err
		}
	}
	result.CompletedAssignments = r.completed.Load()
	return result, ctx.Err()
}

func (r *runner) completePopulationAssignment(ctx context.Context, device *simulatedDevice) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if err := r.syncTrust(ctx, device); err != nil {
			return err
		}
		if err := r.dispatch(ctx, device); err != nil {
			return err
		}
		if len(device.completed) > 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for simulated service assignment: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}
