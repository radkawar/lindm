package loadlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	configv1 "lindm/gen/lindm/config/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// AdvisorySample is the server's own fleet advisory coverage: devices whose
// persisted evaluation binds their current snapshot, host and feed revision.
type AdvisorySample struct {
	ElapsedSeconds float64
	Evaluated      uint64
	Total          uint64
	Findings       uint64
	Error          string `json:",omitempty"`
}

// AdvisoryFeedStatus is the nonsecret publication evidence for one real feed.
type AdvisoryFeedStatus struct {
	ID             string
	SourceURL      string
	SourceSHA256   string
	AdvisoryCount  uint64
	Rejected       int
	CheckedAt      time.Time
	PublishSeconds float64
}

const maxLoadInputBytes = 4 << 20

func readLoadInput(path string) (_ []byte, _ string, resultErr error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	info, err := file.Stat()
	if err != nil {
		return nil, "", err
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxLoadInputBytes {
		return nil, "", errors.New("load input must be a nonempty regular file of at most 4 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxLoadInputBytes+1))
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(data)
	return data, hex.EncodeToString(digest[:]), nil
}

// ReadAdvisoryFeeds loads a strict AdvisoryConfig that must enable refresh of at
// least one real feed; the server performs its normal verified acquisition.
func ReadAdvisoryFeeds(path string) (*configv1.AdvisoryConfig, string, error) {
	data, digest, err := readLoadInput(path)
	if err != nil {
		return nil, "", fmt.Errorf("read advisory feeds: %w", err)
	}
	cfg := new(configv1.AdvisoryConfig)
	if err := protojson.Unmarshal(data, cfg); err != nil {
		return nil, "", fmt.Errorf("decode AdvisoryConfig protobuf JSON: %w", err)
	}
	if err := protovalidate.Validate(cfg); err != nil {
		return nil, "", fmt.Errorf("validate advisory feeds: %w", err)
	}
	if len(cfg.GetFeeds()) == 0 || !cfg.GetRefreshEnabled() {
		return nil, "", errors.New("advisory feeds must configure at least one feed with refreshEnabled")
	}
	return cfg, digest, nil
}

func readPackageBaseline(path string, limit int) ([]*inventoryv1.Package, string, error) {
	data, digest, err := readLoadInput(path)
	if err != nil {
		return nil, "", fmt.Errorf("read package baseline: %w", err)
	}
	batch := new(inventoryv1.PackageBatch)
	if err := protojson.Unmarshal(data, batch); err != nil {
		return nil, "", fmt.Errorf("decode PackageBatch protobuf JSON: %w", err)
	}
	if err := validatePackageBaseline(batch.GetPackages()); err != nil {
		return nil, "", fmt.Errorf("validate package baseline: %w", err)
	}
	if len(batch.GetPackages()) == 0 || len(batch.GetPackages()) > limit {
		return nil, "", errors.New("package baseline must contain between one and -packages records")
	}
	return batch.GetPackages(), digest, nil
}

func encodePackageBaseline(baseline []*inventoryv1.Package) ([]byte, error) {
	if len(baseline) == 0 {
		return nil, nil
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(&inventoryv1.PackageBatch{Packages: baseline})
}

func decodePackageBaseline(data []byte) ([]*inventoryv1.Package, error) {
	if len(data) == 0 {
		return nil, nil
	}
	batch := new(inventoryv1.PackageBatch)
	if err := proto.Unmarshal(data, batch); err != nil {
		return nil, err
	}
	if err := validatePackageBaseline(batch.GetPackages()); err != nil {
		return nil, err
	}
	return batch.GetPackages(), nil
}

// validatePackageBaseline applies the wire PackageBatch rules to each
// 500-package batch the snapshot will actually carry.
func validatePackageBaseline(baseline []*inventoryv1.Package) error {
	for start := 0; start < len(baseline); start += 500 {
		if err := protovalidate.Validate(&inventoryv1.PackageBatch{Packages: baseline[start:min(start+500, len(baseline))]}); err != nil {
			return err
		}
	}
	return nil
}

// waitForAdvisoryPublication holds the workload until every configured feed has
// a successful real publication, so plateaus measure evaluation against it.
func (r *runner) waitForAdvisoryPublication(ctx context.Context, feeds int) ([]AdvisoryFeedStatus, error) {
	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		call, stop := context.WithTimeout(ctx, 30*time.Second)
		response, err := r.owner.Admin.ListAdvisoryFeeds(call, connect.NewRequest(&adminv1.ListAdvisoryFeedsRequest{}))
		stop()
		if err != nil {
			return nil, fmt.Errorf("list advisory feeds: %w", err)
		}
		published := make([]AdvisoryFeedStatus, 0, feeds)
		for _, feed := range response.Msg.GetFeeds() {
			if feed.GetAdvisoryCount() > 0 && feed.GetError() == "" && feed.GetFresh() {
				published = append(published, AdvisoryFeedStatus{ID: feed.GetId(), SourceURL: feed.GetSourceUrl(), SourceSHA256: feed.GetSourceSha256(), AdvisoryCount: feed.GetAdvisoryCount(), Rejected: len(feed.GetRejectedRecords()), CheckedAt: feed.GetCheckedAt().AsTime(), PublishSeconds: time.Since(started).Seconds()})
			}
		}
		if len(published) == feeds {
			return published, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("advisory feeds were not published: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func (r *runner) sampleAdvisories(ctx context.Context, elapsed time.Duration) (AdvisorySample, error) {
	call, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	started := time.Now()
	response, err := r.owner.Admin.GetFleetSummary(call, connect.NewRequest(&adminv1.GetFleetSummaryRequest{RecentActionLimit: 1}))
	r.metrics.observe("GetFleetSummary", time.Since(started), err)
	if err != nil {
		return AdvisorySample{}, fmt.Errorf("sample advisory coverage: %w", err)
	}
	findings := response.Msg.GetFindings()
	if findings == nil {
		return AdvisorySample{}, errors.New("server reported no advisory summary although feeds are configured")
	}
	return AdvisorySample{ElapsedSeconds: elapsed.Seconds(), Evaluated: findings.GetEvaluatedDevices(), Total: findings.GetEvaluatedDevices() + findings.GetUnknownDevices(), Findings: findings.GetCriticalFindings() + findings.GetHighFindings() + findings.GetMediumFindings() + findings.GetLowFindings() + findings.GetOtherFindings()}, nil
}
