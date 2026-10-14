// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"context"
	"errors"
	"fmt"
	"net"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/config"
)

// ConfigureProfiling enables private profiling only on this owned server and
// restarts it before returning its literal loopback HTTP origin. Call once before
// starting load, without racing other fixture lifecycle operations. CPU captures
// take cpuSeconds (1..60); mutex sampling is 1 and block sampling is 1 ms. These
// process-wide rates remain enabled until the owned server stops. No shared
// configuration or process is touched, and no arbitrary target is accepted.
func (f *AuthorityFixture) ConfigureProfiling(ctx context.Context, cpuSeconds uint32) (_ string, resultErr error) {
	if f == nil || f.closed || f.process == nil {
		return "", errors.New("profiling requires a running owned authority fixture")
	}
	document, err := config.Load(f.configPath())
	if err != nil {
		return "", err
	}
	if document.Proto.GetProfiling() != nil {
		return "", errors.New("authority profiling is already configured")
	}
	listener, err := new(net.ListenConfig).Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("reserve authority profiling port: %w", err)
	}
	defer func() {
		if listener != nil {
			resultErr = errors.Join(resultErr, listener.Close())
		}
	}()
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return "", errors.New("authority profiling listener is not TCP")
	}
	document.Proto.Profiling = &configv1.ProfilingConfig{
		Listener:          &configv1.ListenerConfig{Address: "127.0.0.1", Port: uint32(address.Port)},
		CpuProfileSeconds: cpuSeconds, MutexProfileFraction: 1, BlockProfileRateNs: 1000000,
	}
	validator, err := protovalidate.New(protovalidate.WithMessages(document.Proto))
	if err != nil {
		return "", err
	}
	if err := validator.Validate(document.Proto); err != nil {
		return "", err
	}
	encoded, err := protojson.Marshal(document.Proto)
	if err != nil {
		return "", err
	}
	if err := f.writeConfig(encoded); err != nil {
		return "", err
	}
	origin := "http://" + listener.Addr().String()
	closeErr := listener.Close()
	listener = nil
	if closeErr != nil {
		return "", closeErr
	}
	// Like the fixture's admin/device reservations, the port must be released
	// before the subprocess binds it. A collision fails startup, never redirects.
	if err := f.Restart(ctx); err != nil {
		return "", err
	}
	return origin, nil
}
