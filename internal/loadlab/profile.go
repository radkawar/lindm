// SPDX-License-Identifier: Apache-2.0

package loadlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"lindm/internal/devlab"
)

type DatabaseSample struct {
	ElapsedSeconds float64
	Profile        devlab.DatabaseProfile
}
type ProfileArtifact struct {
	ElapsedSeconds float64
	Kind           string
	Path           string
	SHA256         string
	Bytes          int64
}
type diagnosticResult struct {
	Database []DatabaseSample
	Profiles []ProfileArtifact
	Err      error
}
type diagnosticRun struct {
	cancel context.CancelFunc
	done   chan diagnosticResult
}

func (r *runner) startDiagnostics(ctx context.Context, devices int, start, until time.Time) *diagnosticRun {
	if r.options.ProfileDir == "" {
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	run := &diagnosticRun{cancel: cancel, done: make(chan diagnosticResult, 1)}
	go func() {
		result := diagnosticResult{}
		defer func() { run.done <- result }()
		interval := time.NewTicker(10 * time.Second)
		defer interval.Stop()
		delay := 9 * time.Minute
		if r.options.StageDuration < 10*time.Minute {
			delay = r.options.StageDuration / 2
		}
		capture := time.NewTimer(time.Until(start.Add(delay)))
		defer capture.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-interval.C:
				call, stop := context.WithTimeout(ctx, 5*time.Second)
				sample, err := r.fixture.ProfileDatabase(call)
				stop()
				if err != nil {
					if ctx.Err() == nil {
						result.Err = err
					}
					return
				}
				result.Database = append(result.Database, DatabaseSample{ElapsedSeconds: time.Since(start).Seconds(), Profile: sample})
			case <-capture.C:
				for _, kind := range []string{"profile", "mutex", "block"} {
					item, err := captureProfile(ctx, r.profileOrigin, r.options.ProfileDir, devices, kind, time.Since(start))
					if err != nil {
						if ctx.Err() == nil {
							result.Err = err
						}
						return
					}
					result.Profiles = append(result.Profiles, item)
				}
				if next := time.Now().Add(30 * time.Minute); next.Add(40 * time.Second).Before(until) {
					capture.Reset(time.Until(next))
				}
			}
			if !time.Now().Before(until) {
				return
			}
		}
	}()
	return run
}
func (d *diagnosticRun) finish() diagnosticResult {
	if d == nil {
		return diagnosticResult{}
	}
	d.cancel()
	return <-d.done
}
func captureProfile(ctx context.Context, origin, directory string, devices int, kind string, elapsed time.Duration) (artifact ProfileArtifact, resultErr error) {
	call, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(call, http.MethodGet, origin+"/debug/pprof/"+kind, nil)
	if err != nil {
		return artifact, err
	}
	client := &http.Client{Timeout: 40 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		return artifact, err
	}
	defer func() { resultErr = errors.Join(resultErr, response.Body.Close()) }()
	if response.StatusCode != http.StatusOK {
		return artifact, fmt.Errorf("profile %s returned HTTP %d", kind, response.StatusCode)
	}
	path := filepath.Join(directory, fmt.Sprintf("%d-%d-%s.pb.gz", devices, int64(elapsed/time.Second), kind))
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return artifact, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, file.Close())
		if resultErr != nil {
			resultErr = errors.Join(resultErr, os.Remove(path))
		}
	}()
	digest := sha256.New()
	size, err := io.Copy(io.MultiWriter(file, digest), io.LimitReader(response.Body, (16<<20)+1))
	if err != nil {
		return artifact, err
	}
	if size > 16<<20 {
		return artifact, errors.New("profile exceeds16MiB")
	}
	if err := file.Sync(); err != nil {
		return artifact, err
	}
	return ProfileArtifact{ElapsedSeconds: elapsed.Seconds(), Kind: kind, Path: path, SHA256: hex.EncodeToString(digest.Sum(nil)), Bytes: size}, nil
}
