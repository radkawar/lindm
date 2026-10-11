package devlab

import (
	"context"
	"errors"
	"net/http"
	"syscall"
	"time"

	"lindm/internal/config"
)

// OpenHAAuthorityFixture composes the isolated local-authority fixture on the
// replicated laboratory topology: PostgreSQL primary plus synchronous streaming
// standby, an HAProxy L4 TLS-passthrough balancer and two lindmd replicas. Its
// AdminAddress/DeviceAddress and signed origins are the balancer's. Integrations
// and reports are enabled so every background job is supervised.
func OpenHAAuthorityFixture(ctx context.Context, repository, binary string) (*AuthorityFixture, error) {
	return openAuthorityFixture(ctx, repository, binary, authorityHA)
}

func (f *AuthorityFixture) requireHA() error {
	if f.closed || f.ha == nil {
		return errors.New("fixture is not an open HA topology")
	}
	return nil
}

func (f *AuthorityFixture) haClient() (*http.Client, func(), error) {
	tlsConfig, err := trustClient(FixturePath(f.repository))
	if err != nil {
		return nil, nil, err
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, ResponseHeaderTimeout: 3 * time.Second, DisableKeepAlives: true}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return client, transport.CloseIdleConnections, nil
}

// startHA starts the balancer and every stopped replica with its last binary,
// then requires readiness through the balancer's public origin. A full start
// first re-derives replica configs from the current base configuration.
func (f *AuthorityFixture) startHA(ctx context.Context) error {
	client, closeClient, err := f.haClient()
	if err != nil {
		return err
	}
	defer closeClient()
	if !f.ha.running() {
		document, err := config.Load(f.configPath())
		if err != nil {
			return err
		}
		if err := f.ha.writeInstanceConfigs(document.Proto, f.directory); err != nil {
			return err
		}
	}
	if err := f.ha.startProxy(ctx); err != nil {
		return err
	}
	for _, instance := range f.ha.instances {
		if instance.process != nil {
			continue
		}
		binary := instance.binary
		if binary == "" {
			binary = f.binary
		}
		if err := f.ha.startInstance(ctx, instance, binary, client); err != nil {
			return err
		}
	}
	return f.waitBalancer(ctx, client, HAInstanceNames[:]...)
}

// waitBalancer requires the named replicas to be UP in both HAProxy backends
// and the public admin origin to be ready, so a rolling step never drains the
// next replica before its successor can receive traffic.
func (f *AuthorityFixture) waitBalancer(ctx context.Context, client *http.Client, names ...string) error {
	return pollUntil(ctx, time.Minute, func(ctx context.Context) (bool, error) {
		states, err := f.ha.serverStates(ctx)
		if err != nil {
			return false, nil
		}
		for _, name := range names {
			if states["admin/"+name] != "UP" || states["device/"+name] != "UP" {
				return false, nil
			}
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, f.ConsoleOrigin+"/readyz", nil)
		if err != nil {
			return false, err
		}
		response, err := client.Do(request)
		if err != nil {
			return false, nil
		}
		closeErr := response.Body.Close()
		return response.StatusCode == http.StatusNoContent && closeErr == nil, nil
	})
}

// HAEnvironment returns persistable topology identity without secrets.
func (f *AuthorityFixture) HAEnvironment() (HAEnvironment, error) {
	if err := f.requireHA(); err != nil {
		return HAEnvironment{}, err
	}
	return f.ha.environment(), nil
}

// HAInstances returns the current state of every replica. A replica that exited
// without a laboratory signal is reported as not running.
func (f *AuthorityFixture) HAInstances() []HAInstanceState {
	if f.ha == nil {
		return nil
	}
	states := make([]HAInstanceState, 0, len(f.ha.instances))
	for _, instance := range f.ha.instances {
		state := instance.state
		state.Running = instance.process != nil && len(instance.done) == 0
		if exit := instance.exit.Load(); exit != nil {
			state.Exit = *exit
		}
		states = append(states, state)
	}
	return states
}

// FreezeHAInstance stops one replica with SIGSTOP so requests routed to it are
// in flight, without draining. Only KillHAInstance may follow.
func (f *AuthorityFixture) FreezeHAInstance(name string) error {
	if err := f.requireHA(); err != nil {
		return err
	}
	instance, err := f.ha.instance(name)
	if err != nil {
		return err
	}
	if instance.process == nil {
		return errors.New("HA instance is not running")
	}
	return instance.process.Process.Signal(syscall.SIGSTOP)
}

// KillHAInstance crashes one replica with SIGKILL: no drain, no unlock.
func (f *AuthorityFixture) KillHAInstance(name string) error {
	return f.signalHA(name, syscall.SIGKILL)
}

// StopHAInstance drains one replica with SIGTERM, as a rolling upgrade does.
func (f *AuthorityFixture) StopHAInstance(name string) error {
	return f.signalHA(name, syscall.SIGTERM)
}

func (f *AuthorityFixture) signalHA(name string, signal syscall.Signal) error {
	if err := f.requireHA(); err != nil {
		return err
	}
	instance, err := f.ha.instance(name)
	if err != nil {
		return err
	}
	if instance.process == nil {
		return errors.New("HA instance is not running")
	}
	return f.ha.signalInstance(instance, signal)
}

// StartHAInstance starts one stopped replica with the given executable and
// waits for its own and the balancer's readiness.
func (f *AuthorityFixture) StartHAInstance(ctx context.Context, name, binary string) error {
	if err := f.requireHA(); err != nil {
		return err
	}
	instance, err := f.ha.instance(name)
	if err != nil {
		return err
	}
	client, closeClient, err := f.haClient()
	if err != nil {
		return err
	}
	defer closeClient()
	if err := f.ha.startInstance(ctx, instance, binary, client); err != nil {
		return err
	}
	return f.waitBalancer(ctx, client, name)
}

// FailOverHADatabase crashes the primary container and promotes the standby.
func (f *AuthorityFixture) FailOverHADatabase(ctx context.Context) (HAFailover, error) {
	if err := f.requireHA(); err != nil {
		return HAFailover{}, err
	}
	return f.ha.failOver(ctx)
}

// HALockHolders lists granted advisory locks in this fixture's database.
func (f *AuthorityFixture) HALockHolders(ctx context.Context) ([]HALockHolder, error) {
	if err := f.requireHA(); err != nil {
		return nil, err
	}
	return f.ha.lockHolders(ctx, f.DatabaseName)
}

// HAInstanceLog returns one replica's bounded JSON log.
func (f *AuthorityFixture) HAInstanceLog(name string) ([]byte, error) {
	if err := f.requireHA(); err != nil {
		return nil, err
	}
	return f.ha.instanceLog(name)
}

// HAProxyLog returns the balancer's bounded health-check log.
func (f *AuthorityFixture) HAProxyLog(ctx context.Context) (string, error) {
	if err := f.requireHA(); err != nil {
		return "", err
	}
	return f.ha.proxyLog(ctx)
}
