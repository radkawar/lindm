package devlab

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/config"
	"lindm/internal/labexec"
)

func runtimeAuthorizationRestart(ctx context.Context, fixture *AuthorityFixture, owner *OwnerSession, expected *adminv1.AuthorizationState) error {
	document, err := config.Load(fixture.configPath())
	if err != nil {
		return err
	}
	// Configuration is deliberately different, but valid: it must not overwrite
	// the previously accepted runtime source during process startup.
	document.Proto.Authorization = &authv1.AuthorizationPolicy{Roles: []*authv1.RoleDefinition{{Name: "bootstrap-only", Permissions: []string{"fleet.read"}}}}
	encoded, err := protojson.Marshal(document.Proto)
	if err != nil {
		return err
	}
	if err := os.WriteFile(fixture.configPath(), encoded, 0600); err != nil {
		return err
	}
	if err := fixture.Restart(ctx); err != nil {
		return err
	}
	state, err := owner.Admin.GetAuthorization(ctx, connect.NewRequest(&adminv1.GetAuthorizationRequest{}))
	if err != nil {
		return err
	}
	if !proto.Equal(state.Msg.GetAuthorization(), expected) {
		return errors.New("restart allowed bootstrap config to overwrite runtime authority")
	}
	return nil
}

func runtimeAuthorizationReplica(ctx context.Context, fixture *AuthorityFixture, owner *OwnerSession, expected *adminv1.AuthorizationState) (resultErr error) {
	document, err := config.Load(fixture.configPath())
	if err != nil {
		return err
	}
	admin, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer func() {
		if admin != nil {
			resultErr = errors.Join(resultErr, admin.Close())
		}
	}()
	device, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer func() {
		if device != nil {
			resultErr = errors.Join(resultErr, device.Close())
		}
	}()
	adminAddress, adminOK := admin.Addr().(*net.TCPAddr)
	deviceAddress, deviceOK := device.Addr().(*net.TCPAddr)
	if !adminOK || !deviceOK {
		return errors.New("runtime replica listeners did not bind TCP addresses")
	}
	document.Proto.AdminListener.Port = uint32(adminAddress.Port)
	document.Proto.DeviceListener.Port = uint32(deviceAddress.Port)
	encoded, err := protojson.Marshal(document.Proto)
	if err != nil {
		return err
	}
	path := filepath.Join(fixture.directory, "runtime-replica-"+uuid.NewString()+".json")
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, os.Remove(path)) }()
	command, err := newServerCommand(fixture.binary, path, fixture.serverCPUs)
	if err != nil {
		return err
	}
	command.Stdout, command.Stderr = fixture.log, fixture.log
	if err := admin.Close(); err != nil {
		return err
	}
	admin = nil
	if err := device.Close(); err != nil {
		return err
	}
	device = nil
	process, err := labexec.Start(context.WithoutCancel(ctx), command)
	if err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	defer func() {
		process.Signal(syscall.SIGTERM)
		select {
		case err := <-done:
			resultErr = errors.Join(resultErr, err)
		case <-time.After(15 * time.Second):
			process.Signal(syscall.SIGKILL)
			resultErr = errors.Join(resultErr, errors.New("runtime replica required forced shutdown"))
			select {
			case err := <-done:
				resultErr = errors.Join(resultErr, err)
			case <-time.After(5 * time.Second):
				resultErr = errors.Join(resultErr, errors.New("runtime replica cleanup deadline"))
			}
		}
	}()
	// Borrow credentials, not ownership; never call Close on this view because
	// the primary fixture alone owns the database and local authenticator keys.
	replica := &AuthorityFixture{repository: fixture.repository, directory: fixture.directory, ConsoleOrigin: fixture.ConsoleOrigin, AdminAddress: adminAddress.String(), local: fixture.local}
	session, err := replica.newLocalSession(fixture.local.owner)
	if err != nil {
		return err
	}
	// Preserve the logical public origin and TLS name while proving the call
	// reaches the second process, not the primary's dynamically allocated port.
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	session.transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, adminAddress.String())
	}
	defer func() { resultErr = errors.Join(resultErr, session.Close(context.WithoutCancel(ctx))) }()
	ready, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		req, err := http.NewRequestWithContext(ready, http.MethodGet, fixture.ConsoleOrigin+"/readyz", nil)
		if err != nil {
			return err
		}
		response, err := session.client.Do(req)
		if err == nil {
			closeErr := response.Body.Close()
			if closeErr != nil {
				return closeErr
			}
			if response.StatusCode == http.StatusNoContent {
				break
			}
		}
		select {
		case <-ready.Done():
			return fmt.Errorf("runtime replica readiness: %w", ready.Err())
		case <-ticker.C:
		}
	}
	if err := session.localCeremony(ctx, ""); err != nil {
		return err
	}
	state, err := session.Admin.GetAuthorization(ctx, connect.NewRequest(&adminv1.GetAuthorizationRequest{}))
	if err != nil {
		return err
	}
	if !proto.Equal(state.Msg.GetAuthorization(), expected) {
		return errors.New("second server disagrees on runtime authority")
	}
	policy := proto.CloneOf(expected.GetPolicy())
	policy.Roles = append(policy.Roles, &authv1.RoleDefinition{Name: "replica-reader", Permissions: []string{"fleet.read"}})
	updated, err := session.Admin.UpdateAuthorization(ctx, connect.NewRequest(&adminv1.UpdateAuthorizationRequest{RequestId: uuid.NewString(), ExpectedRevision: expected.GetRevision(), Policy: policy, Reason: "qualify cross-instance runtime authorization visibility"}))
	if err != nil {
		return err
	}
	observed, err := owner.Admin.GetAuthorization(ctx, connect.NewRequest(&adminv1.GetAuthorizationRequest{}))
	if err != nil {
		return err
	}
	if !proto.Equal(updated.Msg.GetAuthorization(), observed.Msg.GetAuthorization()) {
		return errors.New("primary did not immediately observe replica policy mutation")
	}
	return nil
}
