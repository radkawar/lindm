package loadlab

import (
	"context"
	"errors"
	"time"
)

func (r *runner) sampleScaleOut(ctx context.Context, elapsed time.Duration) (ScaleOutSample, error) {
	call, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	sample := ScaleOutSample{ElapsedSeconds: elapsed.Seconds()}
	var err error
	sample.Replicas, err = r.fixture.MeasureScaleOut(call)
	if err != nil {
		return sample, err
	}
	if r.remote != nil {
		response, err := r.remote.call(call, generatorRequest{Measure: true})
		if err != nil {
			return sample, err
		}
		if response.Metrics == nil {
			return sample, errors.New("remote generator returned no resource metrics")
		}
		sample.Generator = response.Metrics
	}
	return sample, nil
}
