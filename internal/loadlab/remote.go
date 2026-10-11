package loadlab

import (
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
)

// The remote generator runs only the simulated devices' side of the protocol on
// a separate host. The orchestrator keeps the disposable authority, owner
// session, server/database sampling and SLO decisions. Requests travel over the
// SSH child's stdin/stdout; the only secret sent is each one-use enrollment
// grant, which the generator consumes immediately and never persists.

type generatorRequest struct {
	ID     uint64
	Init   *generatorInit
	Enroll *generatorEnroll
	Stage  *generatorStage
	Export bool
}

type generatorInit struct {
	ExecutionRootJSON []byte
	BootstrapEnvelope []byte
	AdminAddress      string
	DeviceAddress     string
	AgentRelease      string
	AgentProtocol     uint32
	Packages          int
	Baseline          []byte
	Seed              uint64
	AssignmentPercent int
}

type generatorEnroll struct {
	Index  int
	Secret string
}

type generatorStage struct {
	Devices  int
	Duration time.Duration
}

type generatorResponse struct {
	ID         uint64
	Error      string
	DeviceID   string
	Identity   *GeneratorIdentity
	Counters   *generatorCounters
	Histograms map[string]HistogramData
}

// GeneratorIdentity is the remote generator host and executable evidence.
type GeneratorIdentity struct {
	Host     string
	SHA256   string
	Hardware map[string]string
}

type generatorCounters struct {
	Completed, CompletedDevices, InventoryCycles uint64
}

var generatorHostPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
var generatorPathPattern = regexp.MustCompile(`^/[A-Za-z0-9._/-]{1,1000}$`)

type remoteGenerator struct {
	command  *exec.Cmd
	stdin    io.WriteCloser
	writeMu  sync.Mutex
	encoder  *gob.Encoder
	next     atomic.Uint64
	mu       sync.Mutex
	pending  map[uint64]chan generatorResponse
	failure  error
	done     chan struct{}
	identity GeneratorIdentity
}

// startRemoteGenerator launches `lab load-generator` on an SSH alias. The
// binary path is an absolute, pre-staged executable on that host.
func startRemoteGenerator(ctx context.Context, host, binary, sshConfig string, stderr io.Writer) (*remoteGenerator, error) {
	if !generatorHostPattern.MatchString(host) || !generatorPathPattern.MatchString(binary) || (sshConfig != "" && !generatorPathPattern.MatchString(sshConfig)) {
		return nil, errors.New("load: generator host must be an SSH alias and generator binary/SSH config absolute plain paths")
	}
	args := []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=8", "-T"}
	if sshConfig != "" {
		args = append([]string{"-F", sshConfig}, args...)
	}
	command := exec.CommandContext(ctx, "ssh", append(args, host, "--", binary, "load-generator")...)
	command.Stderr = stderr
	command.WaitDelay = 30 * time.Second
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start remote generator: %w", err)
	}
	g := &remoteGenerator{command: command, stdin: stdin, encoder: gob.NewEncoder(stdin), pending: make(map[uint64]chan generatorResponse), done: make(chan struct{})}
	g.identity.Host = host
	go g.read(stdout)
	return g, nil
}

func (g *remoteGenerator) read(stdout io.Reader) {
	defer close(g.done)
	decoder := gob.NewDecoder(stdout)
	for {
		var response generatorResponse
		if err := decoder.Decode(&response); err != nil {
			g.mu.Lock()
			if g.failure == nil {
				g.failure = fmt.Errorf("remote generator stream ended: %w", err)
			}
			for id, ch := range g.pending {
				close(ch)
				delete(g.pending, id)
			}
			g.mu.Unlock()
			return
		}
		g.mu.Lock()
		ch := g.pending[response.ID]
		delete(g.pending, response.ID)
		g.mu.Unlock()
		if ch != nil {
			ch <- response
		}
	}
}

func (g *remoteGenerator) call(ctx context.Context, request generatorRequest) (generatorResponse, error) {
	request.ID = g.next.Add(1)
	ch := make(chan generatorResponse, 1)
	g.mu.Lock()
	if g.failure != nil {
		err := g.failure
		g.mu.Unlock()
		return generatorResponse{}, err
	}
	g.pending[request.ID] = ch
	g.mu.Unlock()
	g.writeMu.Lock()
	err := g.encoder.Encode(&request)
	g.writeMu.Unlock()
	if err != nil {
		return generatorResponse{}, fmt.Errorf("send remote generator request: %w", err)
	}
	select {
	case <-ctx.Done():
		return generatorResponse{}, ctx.Err()
	case response, ok := <-ch:
		if !ok {
			g.mu.Lock()
			defer g.mu.Unlock()
			return generatorResponse{}, g.failure
		}
		if response.Error != "" {
			return response, errors.New(response.Error)
		}
		return response, nil
	}
}

func (g *remoteGenerator) close() error {
	err := g.stdin.Close()
	select {
	case <-g.done:
	case <-time.After(time.Minute):
	}
	return errors.Join(err, g.command.Wait())
}

// ServeGenerator is the remote side: one runner without fixture or owner. It
// exits when the orchestrator closes stdin, closing every simulated device.
func ServeGenerator(ctx context.Context, in io.Reader, out io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	decoder := gob.NewDecoder(in)
	encoder := gob.NewEncoder(out)
	var writeMu sync.Mutex
	send := func(response generatorResponse) {
		writeMu.Lock()
		defer writeMu.Unlock()
		if err := encoder.Encode(&response); err != nil {
			cancel()
		}
	}
	var (
		r       *runner
		mu      sync.Mutex
		devices = map[int]*simulatedDevice{}
		wg      sync.WaitGroup
	)
	defer func() {
		cancel()
		wg.Wait()
		for _, d := range devices {
			d.close()
		}
		if r != nil && r.enrollmentTransport != nil {
			r.enrollmentTransport.CloseIdleConnections()
		}
	}()
	for {
		var request generatorRequest
		if err := decoder.Decode(&request); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if request.Init != nil {
			response := generatorResponse{ID: request.ID}
			if r != nil {
				response.Error = "generator already initialized"
			} else {
				initialized, identity, err := newGeneratorRunner(ctx, request.Init)
				if err != nil {
					response.Error = err.Error()
				} else {
					r, response.Identity = initialized, identity
				}
			}
			send(response)
			continue
		}
		if r == nil {
			send(generatorResponse{ID: request.ID, Error: "generator is not initialized"})
			continue
		}
		wg.Go(func() {
			response := generatorResponse{ID: request.ID}
			switch {
			case request.Enroll != nil:
				call, stop := context.WithTimeout(ctx, 2*time.Minute)
				d, err := r.enrollDevice(call, request.Enroll.Index, request.Enroll.Secret)
				stop()
				if err != nil {
					response.Error = err.Error()
					break
				}
				mu.Lock()
				if devices[request.Enroll.Index] != nil {
					response.Error = "duplicate simulated device index"
					d.close()
				} else {
					devices[request.Enroll.Index] = d
					response.DeviceID = d.id
				}
				mu.Unlock()
			case request.Stage != nil:
				mu.Lock()
				selected := make([]*simulatedDevice, request.Stage.Devices)
				for i := range selected {
					selected[i] = devices[i]
				}
				mu.Unlock()
				for _, d := range selected {
					if d == nil {
						response.Error = "stage references an unenrolled simulated device"
						break
					}
				}
				if response.Error != "" {
					break
				}
				r.options.StageDuration = request.Stage.Duration
				until := time.Now().Add(request.Stage.Duration)
				var loops sync.WaitGroup
				for index, d := range selected {
					loops.Go(func() { r.deviceLoop(ctx, d, index, until) })
				}
				loops.Wait()
				if err := ctx.Err(); err != nil {
					response.Error = err.Error()
					break
				}
				response.Counters = &generatorCounters{Completed: r.completed.Load(), CompletedDevices: r.completedDevices.Load(), InventoryCycles: r.inventoryCycles.Load()}
				response.Histograms = r.metrics.export(true)
			case request.Export:
				response.Histograms = r.metrics.export(true)
				response.Counters = &generatorCounters{Completed: r.completed.Load(), CompletedDevices: r.completedDevices.Load(), InventoryCycles: r.inventoryCycles.Load()}
			default:
				response.Error = "unknown generator request"
			}
			send(response)
		})
	}
}

func newGeneratorRunner(ctx context.Context, init *generatorInit) (*runner, *GeneratorIdentity, error) {
	r := &runner{metrics: &measurements{}, options: Options{Packages: init.Packages, Seed: init.Seed, AssignmentPercent: init.AssignmentPercent}, agentRelease: init.AgentRelease, agentProtocol: init.AgentProtocol}
	baseline, err := decodePackageBaseline(init.Baseline)
	if err != nil {
		return nil, nil, err
	}
	if err := r.initDevices(ctx, init.ExecutionRootJSON, init.BootstrapEnvelope, init.AdminAddress, init.DeviceAddress, baseline); err != nil {
		return nil, nil, err
	}
	identity := &GeneratorIdentity{}
	identity.Hardware, err = hardware(ctx)
	if err != nil {
		return nil, nil, err
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, nil, err
	}
	identity.SHA256, err = binaryDigest(executable)
	if err != nil {
		return nil, nil, err
	}
	return r, identity, nil
}
