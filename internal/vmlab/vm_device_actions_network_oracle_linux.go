//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// actionHostNetworkOracle serves only a random, non-authorizing marker. Its
// listeners are ephemeral; no host route, firewall or namespace is modified.
// QEMU's loopback gateway supplies the allowed endpoint, while the host's actual
// routed IPv4 address supplies an independent, non-allowlisted host endpoint.
type actionHostNetworkOracle struct {
	server                         *http.Server
	allowed, blocked               net.Listener
	allowedURL, blockedURL, marker string
}

func newActionHostNetworkOracle() (_ *actionHostNetworkOracle, err error) {
	// UDP connect selects the local route without transmitting a datagram.
	route, err := net.Dial("udp4", "192.0.2.1:9")
	if err != nil {
		return nil, err
	}
	address, ok := route.LocalAddr().(*net.UDPAddr)
	if err := route.Close(); err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("host oracle route did not expose a UDP address")
	}
	host := address.IP
	if !host.IsGlobalUnicast() || host.IsLoopback() {
		return nil, errors.New("host oracle requires a routed unicast IPv4 address")
	}
	oracle := &actionHostNetworkOracle{marker: uuid.NewString()}
	defer func() {
		if err != nil {
			err = errors.Join(err, oracle.Close())
		}
	}()
	oracle.allowed, err = net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	oracle.blocked, err = net.Listen("tcp4", net.JoinHostPort(host.String(), "0"))
	if err != nil {
		return nil, err
	}
	_, port, err := net.SplitHostPort(oracle.allowed.Addr().String())
	if err != nil {
		return nil, err
	}
	oracle.allowedURL = "http://" + net.JoinHostPort("10.0.2.2", port) + "/" + oracle.marker
	oracle.blockedURL = "http://" + oracle.blocked.Addr().String() + "/" + oracle.marker
	oracle.server = &http.Server{ReadHeaderTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 3 * time.Second, MaxHeaderBytes: 4096,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/"+oracle.marker {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprint(w, oracle.marker)
		})}
	go func() { _ = oracle.server.Serve(oracle.allowed) }()
	go func() { _ = oracle.server.Serve(oracle.blocked) }()
	return oracle, nil
}

func (o *actionHostNetworkOracle) Close() error {
	if o.server != nil {
		return o.server.Close()
	}
	var err error
	if o.allowed != nil {
		err = o.allowed.Close()
	}
	if o.blocked != nil {
		err = errors.Join(err, o.blocked.Close())
	}
	return err
}

func (o *actionHostNetworkOracle) Probe(ctx context.Context, vm *EncryptedVM, blocked bool) error {
	for _, endpoint := range []struct {
		url    string
		denied bool
	}{{o.allowedURL, false}, {o.blockedURL, blocked}} {
		result, err := vm.guest.runResult(ctx, "curl --noproxy '*' --silent --show-error --fail --connect-timeout 3 --max-time 4 "+nativeQuote(endpoint.url), nil, 4096, 6*time.Second)
		if err != nil {
			return err
		}
		if endpoint.denied {
			if result.ExitCode != 28 {
				return fmt.Errorf("quarantine blocked host endpoint did not time out: exit=%d", result.ExitCode)
			}
		} else if result.ExitCode != 0 || strings.TrimSpace(string(result.Stdout)) != o.marker {
			return fmt.Errorf("quarantine allowed host endpoint marker mismatch: exit=%d", result.ExitCode)
		}
	}
	return nil
}
