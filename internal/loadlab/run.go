package loadlab

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	configv1 "lindm/gen/lindm/config/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	enrollmentv1connect "lindm/gen/lindm/enrollment/v1/enrollmentv1connect"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/nativeexec"
	"lindm/internal/devlab"
	"lindm/internal/labexec"
	"lindm/internal/trust"
)

type Options struct {
	Repository        string
	ServerBinary      string
	Stages            []int
	StageDuration     time.Duration
	Packages          int
	AssignmentPercent int
	EnrollmentWorkers int
	Seed              uint64
	PoolSize          uint32
	ProfileDir        string
	DatabaseStorage   string
	GeneratorCPUs     string
	ServerCPUs        string
	PostgresCPUs      string
	// ListenAddress binds the server listeners to one local IPv4 address, for
	// example a direct-link address reached by a remote generator.
	ListenAddress string
	// GeneratorHost/GeneratorBinary run simulated devices on another host via
	// SSH; empty keeps the co-located in-process generator.
	GeneratorHost   string
	GeneratorBinary string
	// GeneratorSSHConfig optionally selects a private ssh_config (-F) for the
	// generator connection, e.g. a direct-link HostName and pinned known_hosts.
	GeneratorSSHConfig string
	// AdvisoryFeeds is a strict protobuf JSON AdvisoryConfig enabling real feed
	// refresh and background advisory evaluation in the server under test.
	AdvisoryFeeds string
	// PackageBaseline is a protobuf JSON PackageBatch of recorded native
	// packages placed first in every snapshot; synthetic packages pad the rest.
	PackageBaseline string
	// PostgresSettings are allowlisted dedicated-cluster tuning parameters.
	PostgresSettings []string
}
type Sample struct {
	ElapsedSeconds float64
	Server         devlab.AuthorityMetrics
}
type Stage struct {
	Devices                    int
	DurationSeconds            float64
	EnrollmentSeconds          float64
	EnrollmentRPC              map[string]RPCResult
	RPC                        map[string]RPCResult
	Samples                    []Sample
	DatabaseGrowthBytes        int64
	ServerCPUSeconds           float64
	ServerCPUCoresMean         float64
	PeakRSSBytes               uint64
	PeakActiveConnections      int
	PoolFullyActiveSamples     int
	CompletedAssignments       uint64
	CompletedPeriodicSnapshots uint64
	ExpectedPeriodicSnapshots  uint64
	SLOBreached                bool
	DatabaseProfiles           []DatabaseSample
	Profiles                   []ProfileArtifact
	AdvisorySamples            []AdvisorySample
	AdvisoryMinEvaluatedRatio  float64
}
type Result struct {
	StartedAt              time.Time
	FinishedAt             time.Time
	Hardware               map[string]string
	GoVersion              string
	ServerSHA256           string
	GeneratorSHA256        string
	SimulatedAgentRelease  string
	SimulatedAgentProtocol uint32
	Options                Options
	ClockTicksPerSecond    float64
	PoolLimit              int
	HeartbeatSeconds       int
	ManagementSeconds      int
	InventorySeconds       int
	JitterPercent          int
	GeneratorColocated     bool
	Generator              *GeneratorIdentity
	PackageBaselineSHA256  string
	AdvisoryFeedsSHA256    string
	AdvisoryFeeds          []AdvisoryFeedStatus
	Environment            devlab.LoadExperimentEnvironment
	HostContention         HostContention
	Stages                 []Stage
	LargestPassingStage    int
	FirstFailingStage      int
	Failure                string
}
type runner struct {
	options             Options
	fixture             *devlab.AuthorityFixture
	owner               *devlab.OwnerSession
	authority           *trust.Authority
	verifier            *trust.ExecutionVerifier
	bootstrap           *trust.Bootstrap
	roots               *x509.CertPool
	rootDigest          []byte
	enrollment          enrollmentv1connect.EnrollmentServiceClient
	enrollmentTransport *http.Transport
	profile             *adminv1.ProfileRevision
	packages            packageData
	historicalHost      *inventoryv1.HostObservation
	metrics             *measurements
	completed           atomic.Uint64
	completedDevices    atomic.Uint64
	inventoryCycles     atomic.Uint64
	profileOrigin       string
	agentRelease        string
	agentProtocol       uint32
	// effects, when set, journals each simulated service execution before its
	// report; the HA lane uses it to detect duplicate effects.
	effects       func(device, action string, sequence uint64) error
	deviceAddress string
	baseline      []*inventoryv1.Package
	remote        *remoteGenerator
	advisories    bool
	// demo assigns console demo hosts by enrollment index; nil for capacity.
	demo []*demoDevice
}

// prepare composes the same real authority, enrollment and inventory workload for
// capacity runs and caller-owned console fixtures. The caller closes owner and
// enrollment transport after successful initialization.
func (r *runner) prepare(ctx context.Context) (resultErr error) {
	material, err := r.fixture.ReadAgentFixture(ctx)
	if err != nil {
		return err
	}
	r.agentRelease, r.agentProtocol, err = r.fixture.ReleaseIdentity(ctx)
	if err != nil {
		return err
	}
	update, err := r.fixture.ConfigureServiceDispatch(ctx)
	if err != nil {
		return err
	}
	r.owner, err = r.fixture.OpenOwnerSession(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if resultErr != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			resultErr = errors.Join(resultErr, r.owner.Close(cleanup))
			if r.enrollmentTransport != nil {
				r.enrollmentTransport.CloseIdleConnections()
			}
		}
	}()
	if _, err := r.owner.Admin.UpdateExecutionAuthority(ctx, connect.NewRequest(&adminv1.UpdateExecutionAuthorityRequest{Update: update, Reason: "disposable capacity execution authority"})); err != nil {
		return err
	}
	if r.demo != nil {
		// SeedDemo publishes its own catalog instead of the capacity workload.
		return r.initDevices(ctx, material.ExecutionRootJSON, material.BootstrapEnvelope, r.fixture.AdminAddress, r.fixture.DeviceAddress, r.baseline)
	}
	published, err := r.owner.Admin.PublishProfileRevision(ctx, connect.NewRequest(&adminv1.PublishProfileRevisionRequest{RequestId: uuid.NewString(), ProfileId: uuid.NewString(), Reason: "disposable capacity service profile", Spec: &policyv1.ResourceProfile{Name: "Synthetic capacity workload", Resources: []*policyv1.ProfileResource{{ResourceId: uuid.NewString(), Desired: &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, CanonicalKey: "capacity-synthetic.service"}, State: &resourcev1.ResourceDesiredState_SystemdService{SystemdService: &resourcev1.SystemdServiceDesired{Unit: "capacity-synthetic.service", Runtime: resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, Enablement: resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED}}}, Ownership: &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN}, Verification: &resourcev1.VerificationPolicy{MaxAgeSeconds: 1800, Checks: []resourcev1.HealthCheck{resourcev1.HealthCheck_HEALTH_CHECK_NATIVE_STATE}}}}}}))
	if err != nil {
		return err
	}
	r.profile = published.Msg.GetRevision()
	return r.initDevices(ctx, material.ExecutionRootJSON, material.BootstrapEnvelope, r.fixture.AdminAddress, r.fixture.DeviceAddress, r.baseline)
}

// initDevices builds only the device-side protocol state shared by the local
// runner and a remote generator: verified bootstrap, transport roots, the
// enrollment client and deterministic package batches.
func (r *runner) initDevices(ctx context.Context, rootJSON, envelope []byte, adminAddress, deviceAddress string, baseline []*inventoryv1.Package) error {
	var err error
	r.authority, err = trust.New()
	if err != nil {
		return err
	}
	r.bootstrap, err = r.authority.VerifyBootstrap(ctx, rootJSON, envelope, time.Now())
	if err != nil {
		return err
	}
	r.verifier, err = r.authority.NewExecutionVerifier(r.bootstrap)
	if err != nil {
		return err
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(r.bootstrap.Root)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(encoded)
	r.rootDigest = digest[:]
	r.roots = x509.NewCertPool()
	if !r.roots.AppendCertsFromPEM(r.bootstrap.Bundle.GetTransportCaPem()) {
		return errors.New("missing transport roots")
	}
	r.deviceAddress = deviceAddress
	r.enrollmentTransport = r.transport(adminAddress, nil)
	r.enrollment = enrollmentv1connect.NewEnrollmentServiceClient(&http.Client{Transport: r.enrollmentTransport, Timeout: 30 * time.Second}, r.bootstrap.Bundle.GetEnrollmentOrigin(), connect.WithInterceptors(r.metrics))
	r.packages, err = packages(r.options.Packages, baseline)
	return err
}

// Run has no endpoint/credential override: it always owns a newly migrated
// disposable database and real lindmd child. No shared application data is used.
func Run(ctx context.Context, options Options) (result Result, resultErr error) {
	if options.PoolSize == 0 {
		options.PoolSize = 8
	}
	if len(options.Stages) == 0 || len(options.Stages) > 8 || options.StageDuration < time.Minute || options.StageDuration > 3*time.Hour || options.Packages < 1 || options.Packages > 5000 || options.AssignmentPercent < 1 || options.AssignmentPercent > 100 || options.EnrollmentWorkers < 1 || options.EnrollmentWorkers > 64 {
		return result, errors.New("load: invalid bounded workload options")
	}
	previous := 0
	for _, n := range options.Stages {
		if n <= previous || n > 100000 {
			return result, errors.New("load: stages must increase within 1..100000 devices")
		}
		previous = n
	}
	remote := options.GeneratorHost != "" || options.GeneratorBinary != ""
	if remote && (options.GeneratorHost == "" || options.GeneratorBinary == "" || options.GeneratorCPUs != "") {
		return result, errors.New("load: remote generation requires -generator-host and -generator-binary and excludes -generator-cpus")
	}
	result = Result{StartedAt: time.Now().UTC(), Options: options, GoVersion: runtime.Version(), PoolLimit: int(options.PoolSize), HeartbeatSeconds: 60, ManagementSeconds: 20, InventorySeconds: 600, JitterPercent: 10, GeneratorColocated: !remote}
	defer func() {
		result.FinishedAt = time.Now().UTC()
		if resultErr != nil {
			result.Failure = resultErr.Error()
		}
	}()
	var err error
	result.Hardware, err = hardware(ctx)
	if err != nil {
		return result, err
	}
	result.ClockTicksPerSecond, err = strconv.ParseFloat(strings.TrimSpace(result.Hardware["clock_ticks"]), 64)
	if err != nil || result.ClockTicksPerSecond <= 0 {
		return result, errors.New("invalid Linux clock tick rate")
	}
	result.ServerSHA256, err = binaryDigest(options.ServerBinary)
	if err != nil {
		return result, err
	}
	executable, err := os.Executable()
	if err != nil {
		return result, err
	}
	result.GeneratorSHA256, err = binaryDigest(executable)
	if err != nil {
		return result, err
	}
	r := &runner{options: options, metrics: &measurements{}}
	var advisories *configv1.AdvisoryConfig
	if options.AdvisoryFeeds != "" {
		advisories, result.AdvisoryFeedsSHA256, err = ReadAdvisoryFeeds(options.AdvisoryFeeds)
		if err != nil {
			return result, err
		}
		r.advisories = true
	}
	if options.PackageBaseline != "" {
		r.baseline, result.PackageBaselineSHA256, err = readPackageBaseline(options.PackageBaseline, options.Packages)
		if err != nil {
			return result, err
		}
	}
	r.fixture, err = devlab.OpenLoadAuthorityFixture(ctx, options.Repository, options.ServerBinary, devlab.LoadAuthorityOptions{DatabaseStorage: options.DatabaseStorage, ServerCPUs: options.ServerCPUs, PostgresCPUs: options.PostgresCPUs, ListenAddress: options.ListenAddress, Advisories: advisories, PostgresSettings: options.PostgresSettings})
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, r.fixture.Close()) }()
	result.Environment = r.fixture.ExperimentEnvironment()
	if err := r.fixture.ConfigurePool(ctx, options.PoolSize); err != nil {
		return result, err
	}
	if options.ProfileDir != "" {
		if err := os.Mkdir(options.ProfileDir, 0700); err != nil {
			return result, err
		}
		if err := r.fixture.EnableStatementProfiling(ctx); err != nil {
			return result, err
		}
		probe, err := r.fixture.ProfileDatabase(ctx)
		if err != nil {
			return result, err
		}
		if !probe.Statements.Available {
			return result, errors.New("owned database pg_stat_statements profiling is unavailable")
		}
		r.profileOrigin, err = r.fixture.ConfigureProfiling(ctx, 30)
		if err != nil {
			return result, err
		}
	}
	if err := r.prepare(ctx); err != nil {
		return result, err
	}
	result.SimulatedAgentRelease, result.SimulatedAgentProtocol = r.agentRelease, r.agentProtocol
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		resultErr = errors.Join(resultErr, r.owner.Close(cleanup))
	}()
	if advisories != nil {
		result.AdvisoryFeeds, err = r.waitForAdvisoryPublication(ctx, len(advisories.GetFeeds()))
		if err != nil {
			return result, err
		}
	}
	if remote {
		if r.remote, err = r.startGenerator(ctx); err != nil {
			return result, err
		}
		defer func() { resultErr = errors.Join(resultErr, r.remote.close()) }()
		result.Generator = &r.remote.identity
		result.GeneratorSHA256 = r.remote.identity.SHA256
	}
	defer r.enrollmentTransport.CloseIdleConnections()
	sampler, err := NewHostSampler(HostSamplerOptions{CPUs: CPUConfig{GeneratorCPUs: options.GeneratorCPUs, ServerCPUs: options.ServerCPUs, PostgresCPUs: options.PostgresCPUs}, ServerPID: r.fixture.ProcessID, Interval: 10 * time.Second})
	if err != nil {
		return result, err
	}
	if err := sampler.Start(ctx); err != nil {
		return result, err
	}
	defer func() {
		sampler.Close()
		result.HostContention = sampler.Snapshot()
	}()
	var devices []*simulatedDevice
	defer func() {
		for _, d := range devices {
			d.close()
		}
	}()
	enrolled := 0
	for _, n := range options.Stages {
		stage := Stage{Devices: n}
		start := time.Now()
		if r.remote != nil {
			err = r.enrollRemote(ctx, enrolled, n)
			if err == nil {
				enrolled = n
			}
		} else {
			var added []*simulatedDevice
			added, err = r.enrollBatch(ctx, len(devices), n)
			devices = append(devices, added...)
			enrolled = len(devices)
		}
		stage.EnrollmentSeconds = time.Since(start).Seconds()
		if r.remote != nil {
			if exported, exportErr := r.remote.call(ctx, generatorRequest{Export: true}); exportErr != nil {
				err = errors.Join(err, exportErr)
			} else {
				err = errors.Join(err, r.metrics.merge(exported.Histograms))
				r.syncCounters(exported.Counters)
			}
		}
		stage.EnrollmentRPC = r.metrics.snapshot(true)
		if err != nil {
			stage.SLOBreached = true
			result.Stages = append(result.Stages, stage)
			result.FirstFailingStage = n
			return result, fmt.Errorf("enroll capacity stage: %w", err)
		}
		stage, err = r.stage(ctx, devices, enrolled, stage, result.ClockTicksPerSecond)
		result.Stages = append(result.Stages, stage)
		if err != nil {
			return result, err
		}
		if stage.SLOBreached {
			result.FirstFailingStage = n
			break
		}
		result.LargestPassingStage = n
	}
	return result, nil
}
func (r *runner) enrollBatch(ctx context.Context, start, end int) ([]*simulatedDevice, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	devices := make([]*simulatedDevice, end-start)
	var next atomic.Int64
	next.Store(int64(start))
	var wg sync.WaitGroup
	var first error
	var once sync.Once
	for range min(r.options.EnrollmentWorkers, end-start) {
		wg.Go(func() {
			for {
				index := int(next.Add(1)) - 1
				if index >= end || ctx.Err() != nil {
					return
				}
				call, stop := context.WithTimeout(ctx, 2*time.Minute)
				d, err := r.enroll(call, index)
				stop()
				if err != nil {
					once.Do(func() { first = err; cancel() })
					return
				}
				devices[index-start] = d
			}
		})
	}
	wg.Wait()
	completed := devices[:0]
	for _, d := range devices {
		if d != nil {
			completed = append(completed, d)
		}
	}
	return completed, first
}

// enrollRemote creates each one-use grant here and sends only its secret to the
// remote generator, then assigns the returned device like a local enrollment.
func (r *runner) enrollRemote(ctx context.Context, start, end int) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var next atomic.Int64
	next.Store(int64(start))
	var wg sync.WaitGroup
	var first error
	var once sync.Once
	for range min(r.options.EnrollmentWorkers, end-start) {
		wg.Go(func() {
			for {
				index := int(next.Add(1)) - 1
				if index >= end || ctx.Err() != nil {
					return
				}
				call, stop := context.WithTimeout(ctx, 2*time.Minute)
				err := func() error {
					secret, err := r.grant(call, index)
					if err != nil {
						return err
					}
					response, err := r.remote.call(call, generatorRequest{Enroll: &generatorEnroll{Index: index, Secret: secret}})
					if err != nil {
						return fmt.Errorf("device %d: remote enrollment: %w", index, err)
					}
					return r.assign(call, index, response.DeviceID)
				}()
				stop()
				if err != nil {
					once.Do(func() { first = err; cancel() })
					return
				}
			}
		})
	}
	wg.Wait()
	return first
}

func (r *runner) startGenerator(ctx context.Context) (*remoteGenerator, error) {
	material, err := r.fixture.ReadAgentFixture(ctx)
	if err != nil {
		return nil, err
	}
	baseline, err := encodePackageBaseline(r.baseline)
	if err != nil {
		return nil, err
	}
	g, err := startRemoteGenerator(ctx, r.options.GeneratorHost, r.options.GeneratorBinary, r.options.GeneratorSSHConfig, os.Stderr)
	if err != nil {
		return nil, err
	}
	call, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	response, err := g.call(call, generatorRequest{Init: &generatorInit{ExecutionRootJSON: material.ExecutionRootJSON, BootstrapEnvelope: material.BootstrapEnvelope, AdminAddress: r.fixture.AdminAddress, DeviceAddress: r.fixture.DeviceAddress, AgentRelease: r.agentRelease, AgentProtocol: r.agentProtocol, Packages: r.options.Packages, Baseline: baseline, Seed: r.options.Seed, AssignmentPercent: r.options.AssignmentPercent}})
	if err == nil && response.Identity == nil {
		err = errors.New("remote generator returned no identity")
	}
	if err != nil {
		return nil, errors.Join(fmt.Errorf("initialize remote generator: %w", err), g.close())
	}
	host := g.identity.Host
	g.identity = *response.Identity
	g.identity.Host = host
	return g, nil
}

func (r *runner) stage(ctx context.Context, devices []*simulatedDevice, count int, stage Stage, ticks float64) (result Stage, resultErr error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	before, err := r.sample(ctx)
	if err != nil {
		return stage, err
	}
	initialCompleted := r.completed.Load()
	initialInventoryCycles := r.inventoryCycles.Load()
	start := time.Now()
	until := start.Add(r.options.StageDuration)
	diagnostics := r.startDiagnostics(ctx, count, start, until)
	defer func() {
		captured := diagnostics.finish()
		result.DatabaseProfiles, result.Profiles = captured.Database, captured.Profiles
		resultErr = errors.Join(resultErr, captured.Err)
	}()
	done := make(chan error, 1)
	if r.remote != nil {
		go func() {
			response, err := r.remote.call(ctx, generatorRequest{Stage: &generatorStage{Devices: count, Duration: r.options.StageDuration}})
			if err == nil {
				r.syncCounters(response.Counters)
				err = r.metrics.merge(response.Histograms)
			}
			done <- err
		}()
	} else {
		var wg sync.WaitGroup
		for index, d := range devices {
			wg.Go(func() { r.deviceLoop(ctx, d, index, until) })
		}
		go func() { wg.Wait(); done <- nil }()
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	advisoryTicker := time.NewTicker(30 * time.Second)
	defer advisoryTicker.Stop()
	stage.AdvisoryMinEvaluatedRatio = 1
	for {
		select {
		case <-ctx.Done():
			<-done
			return stage, ctx.Err()
		case err := <-done:
			if err != nil {
				return stage, fmt.Errorf("simulated device workload: %w", err)
			}
			after, err := r.sample(ctx)
			if err != nil {
				return stage, err
			}
			stage.DurationSeconds = time.Since(start).Seconds()
			stage.DatabaseGrowthBytes = after.DatabaseBytes - before.DatabaseBytes
			stage.ServerCPUSeconds = float64(after.CPUClockTicks-before.CPUClockTicks) / ticks
			stage.ServerCPUCoresMean = stage.ServerCPUSeconds / stage.DurationSeconds
			stage.RPC = r.metrics.snapshot(true)
			stage.CompletedAssignments = r.completed.Load() - initialCompleted
			commits := stage.RPC["CommitPackageSnapshot"]
			stage.CompletedPeriodicSnapshots = commits.Calls - commits.Errors
			stage.ExpectedPeriodicSnapshots = max(r.inventoryCycles.Load()-initialInventoryCycles, uint64(count)*uint64(r.options.StageDuration/(11*time.Minute)))
			stage.SLOBreached = breached(stage.RPC)
			expected := uint64(0)
			for index := range count {
				if index%100 < r.options.AssignmentPercent {
					expected++
				}
			}
			stage.SLOBreached = stage.SLOBreached || r.completedDevices.Load() != expected || stage.RPC["GetSyncState"].Calls < uint64(count) || stage.RPC["GetResourceWork"].Calls < uint64(count)
			if r.options.StageDuration >= 11*time.Minute && !snapshotsComplete(stage.CompletedPeriodicSnapshots, stage.ExpectedPeriodicSnapshots, 0) {
				stage.SLOBreached = true
			}
			if r.advisories && advisoryFreshnessBreached(stage.AdvisorySamples) {
				stage.SLOBreached = true
			}
			return stage, nil
		case <-advisoryTicker.C:
			if !r.advisories {
				continue
			}
			// A failed or timed-out console summary read is recorded and
			// breaches the plateau; it does not discard the plateau's evidence.
			sample, err := r.sampleAdvisories(ctx, time.Since(start))
			if err != nil {
				if ctx.Err() != nil {
					<-done
					return stage, ctx.Err()
				}
				sample = AdvisorySample{ElapsedSeconds: time.Since(start).Seconds(), Error: err.Error()}
			}
			stage.AdvisorySamples = append(stage.AdvisorySamples, sample)
			if sample.ElapsedSeconds >= advisoryFreshnessWarmup.Seconds() && sample.Total > 0 {
				stage.AdvisoryMinEvaluatedRatio = min(stage.AdvisoryMinEvaluatedRatio, float64(sample.Evaluated)/float64(sample.Total))
			}
		case <-ticker.C:
			sample, err := r.sample(ctx)
			if err != nil {
				cancel()
				<-done
				return stage, err
			}
			stage.Samples = append(stage.Samples, Sample{ElapsedSeconds: time.Since(start).Seconds(), Server: sample})
			stage.PeakRSSBytes = max(stage.PeakRSSBytes, sample.RSSBytes)
			stage.PeakActiveConnections = max(stage.PeakActiveConnections, sample.ActiveConnections)
			if sample.ActiveConnections >= sample.PoolLimit {
				stage.PoolFullyActiveSamples++
			}
		}
	}
}

// advisoryFreshnessWarmup lets newly enrolled devices' first evaluations drain.
// Afterwards at least 80% of active devices must have an evaluation binding
// their current snapshot, host observation and feed revision: at the 10-minute
// inventory cadence that bounds steady-state evaluation lag near two minutes.
const advisoryFreshnessWarmup = 5 * time.Minute
const advisoryMinimumEvaluatedRatio = 0.8

func advisoryFreshnessBreached(samples []AdvisorySample) bool {
	checked := false
	for _, sample := range samples {
		if sample.Error != "" {
			return true
		}
		if sample.ElapsedSeconds < advisoryFreshnessWarmup.Seconds() {
			continue
		}
		checked = true
		if sample.Total == 0 || float64(sample.Evaluated) < advisoryMinimumEvaluatedRatio*float64(sample.Total) {
			return true
		}
	}
	return !checked
}

// syncCounters adopts the remote generator's cumulative device counters, so
// stage deltas use one source rather than mixing local and remote origins.
func (r *runner) syncCounters(counters *generatorCounters) {
	if counters == nil {
		return
	}
	r.completed.Store(counters.Completed)
	r.completedDevices.Store(counters.CompletedDevices)
	r.inventoryCycles.Store(counters.InventoryCycles)
}
func (r *runner) sample(ctx context.Context) (devlab.AuthorityMetrics, error) {
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return r.fixture.Measure(call)
}
func (r *runner) deviceLoop(ctx context.Context, d *simulatedDevice, index int, until time.Time) {
	now := until.Add(-r.options.StageDuration)
	random := rand.New(rand.NewPCG(r.options.Seed, uint64(index)+1))
	management := now.Add(time.Duration(random.Int64N(int64(20 * time.Second))))
	heartbeat := now.Add(time.Duration(random.Int64N(int64(time.Minute))))
	// Inventory continues each device's own cadence from its last collection
	// (enrollment or the previous plateau), as an agent does; the server
	// rejects collections closer than its admission interval.
	inventory := now.Add(jitter(random, 10*time.Minute))
	if !d.lastInventory.IsZero() {
		inventory = d.lastInventory.Add(jitter(random, 10*time.Minute))
	}
	for {
		next := minTime(management, heartbeat, inventory)
		if !next.Before(until) {
			return
		}
		timer := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		call, cancel := context.WithTimeout(ctx, 30*time.Second)
		var err error
		switch next {
		case management:
			err = r.syncTrust(call, d)
			if err == nil {
				err = r.dispatch(call, d)
			}
			management = time.Now().Add(jitter(random, 20*time.Second))
		case heartbeat:
			_, err = d.client.GetSyncState(call, connect.NewRequest(&devicev1.GetSyncStateRequest{SessionEpoch: d.epoch}))
			heartbeat = time.Now().Add(jitter(random, time.Minute))
		case inventory:
			err = r.inventory(call, d, index)
			inventory = time.Now().Add(jitter(random, 10*time.Minute))
			if err != nil && d.inventoryUpload != nil {
				// Like the agent's spool, an admitted-but-unfinished or
				// deferred upload is flushed again on the next ~1 minute
				// cycle, not held until the next collection.
				inventory = time.Now().Add(jitter(random, time.Minute))
			}
		}
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			var rpcErr *connect.Error
			if !errors.As(err, &rpcErr) {
				r.metrics.observe("HarnessProtocol", 0, err)
			}
			code := connect.CodeOf(err)
			if code != connect.CodeUnavailable && code != connect.CodeDeadlineExceeded && code != connect.CodeResourceExhausted {
				return
			}
		}
	}
}
func jitter(random *rand.Rand, base time.Duration) time.Duration {
	return base - base/10 + time.Duration(random.Int64N(int64(base/5)))
}
func minTime(a, b, c time.Time) time.Time {
	if b.Before(a) {
		a = b
	}
	if c.Before(a) {
		a = c
	}
	return a
}
func hardware(ctx context.Context) (map[string]string, error) {
	result := map[string]string{}
	for name, args := range map[string][]string{"cpu": {"lscpu"}, "disk": {"lsblk", "-o", "NAME,MODEL,SIZE,ROTA,TYPE,FSTYPE,MOUNTPOINTS"}, "kernel": {"uname", "-srvmo"}, "clock_ticks": {"getconf", "CLK_TCK"}} {
		output := nativeexec.NewBuffer(65536)
		err := labexec.Run(ctx, labexec.Command{Path: args[0], Args: args[1:], Stdout: output, Timeout: 5 * time.Second})
		if err == nil && output.Truncated() {
			err = errors.New("hardware evidence exceeds bound")
		}
		if err != nil {
			return nil, fmt.Errorf("record %s: %w", name, err)
		}
		result[name] = output.String()
	}
	memory, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return nil, err
	}
	result["memory"] = string(memory)
	for name, path := range map[string]string{"process_limits": "/proc/self/limits", "initial_load_average": "/proc/loadavg"} {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		result[name] = string(data)
	}
	return result, nil
}

func binaryDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	if err := errors.Join(copyErr, file.Close()); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
