package devlab

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/devlab/webauthnlab"
	"lindm/internal/trust"
)

// OpenSplitDeviceActionAuthorityFixture keeps admin on loopback and serves devices
// on the specified LAN IPv4. Its run-owned TLS leaf covers that IP and localhost;
// its signed bootstrap carries the actual device origin. Close owns all resources.
func OpenSplitDeviceActionAuthorityFixture(ctx context.Context, repository, binary string, device netip.Addr, options LoadAuthorityOptions) (*AuthorityFixture, error) {
	if err := validateSplitDevice(device); err != nil {
		return nil, err
	}
	options.splitDevice = device
	return openAuthorityFixtureWithOptions(ctx, repository, binary, authorityDeviceActions, options)
}

// ControlPlaneHandle transfers public trust and a pre-enrolled lane-only owner.
// Its password and software-authenticator private key are secrets. Send over
// authenticated SSH and, if persisted, use an exclusive owner-only file. Only
// the remote lane may use this credential after export. Disposable controllers
// disable the account at teardown; persistent lanes retain their own updated
// credential counters. No short-lived enrollment remains pending in a queue.
type ControlPlaneHandle struct {
	ConsoleOrigin        string `json:"console_origin"`
	AdminPort            uint16 `json:"admin_port"`
	DeviceOrigin         string `json:"device_origin"`
	DatabaseName         string `json:"database_name"`
	TransportCAPEM       []byte `json:"transport_ca_pem"`
	ExecutionRootJSON    []byte `json:"execution_root_json"`
	BootstrapEnvelope    []byte `json:"bootstrap_envelope"`
	AccountID            string `json:"account_id"`
	Username             string `json:"username"`
	Password             []byte `json:"password"`
	WebAuthnCredentialID []byte `json:"webauthn_credential_id"`
	WebAuthnPrivateKey   []byte `json:"webauthn_private_key"`
	WebAuthnCounter      uint32 `json:"webauthn_counter"`
}

// ClearCredentials releases the handle's transferred secrets, including on a
// cancelled handoff. It does not revoke the account; the controller owns teardown.
func (h *ControlPlaneHandle) ClearCredentials() {
	clear(h.Password)
	clear(h.WebAuthnCredentialID)
	clear(h.WebAuthnPrivateKey)
	h.Password, h.WebAuthnCredentialID, h.WebAuthnPrivateKey = nil, nil, nil
	h.WebAuthnCounter = 0
}

type connectedAuthority struct {
	tls      *tls.Config
	material AgentFixture
}

// ExportControlPlane creates and enrolls a distinct owner account for a remote
// lane, or returns the same initial handoff for a persistent named account.
// Persistent lanes must restore their latest counters with
// ConnectPersistentAuthorityFixture, never replay the initial credential.
// The caller owns the returned secrets; never log the handle. Like Close,
// this operation must not race another controller fixture lifecycle operation.
func (f *AuthorityFixture) ExportControlPlane(ctx context.Context, username string) (*ControlPlaneHandle, error) {
	if f == nil || f.closed || f.connected != nil || f.local == nil {
		return nil, errors.New("export control plane requires a live controller-owned local authority fixture")
	}
	if f.persistent {
		saved, err := f.persistedExport(username)
		if err != nil || saved != nil {
			return saved, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	origin, err := url.Parse(f.ConsoleOrigin)
	if err != nil || origin.Scheme != "https" || origin.Hostname() != "localhost" {
		return nil, errors.New("export control plane requires a localhost HTTPS console origin")
	}
	port, err := strconv.ParseUint(origin.Port(), 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("export control plane requires an allocated admin port")
	}
	material, err := f.ReadAgentFixture(ctx)
	if err != nil {
		return nil, fmt.Errorf("read exported agent fixture: %w", err)
	}
	ca, err := os.ReadFile(filepath.Join(f.transportTrustDirectory(), "transport-ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("read exported transport CA: %w", err)
	}
	enrollment, err := f.CreateAcceptanceEnrollment(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("create remote owner enrollment: %w", err)
	}
	defer func() { enrollment.Secret = "" }()
	f.exportedAccounts = append(f.exportedAccounts, enrollment.GetAccountId())
	account, err := newLocalAccount(username, enrollment.GetAccountId())
	if err != nil {
		return nil, fmt.Errorf("create remote owner credential: %w", err)
	}
	defer (&localAuthority{owner: account}).close()
	session, err := f.newLocalSession(account)
	if err != nil {
		return nil, fmt.Errorf("open remote owner enrollment: %w", err)
	}
	defer session.transport.CloseIdleConnections()
	if err := session.localCeremony(ctx, enrollment.GetSecret()); err != nil {
		return nil, fmt.Errorf("enroll remote owner before handoff: %w", err)
	}
	credentialID, privateKey, err := account.authenticator.Export()
	if err != nil {
		return nil, fmt.Errorf("export remote owner authenticator: %w", err)
	}
	handle := &ControlPlaneHandle{
		ConsoleOrigin: f.ConsoleOrigin, AdminPort: uint16(port), DeviceOrigin: f.DeviceOrigin,
		DatabaseName: f.DatabaseName, TransportCAPEM: ca,
		ExecutionRootJSON: material.ExecutionRootJSON, BootstrapEnvelope: material.BootstrapEnvelope,
		AccountID: account.id, Username: account.username, Password: bytes.Clone(account.password),
		WebAuthnCredentialID: credentialID, WebAuthnPrivateKey: privateKey, WebAuthnCounter: account.counter,
	}
	if f.persistent {
		if err := writePersistentJSON(exportedAccountPath(f.directory, username), handle); err != nil {
			handle.ClearCredentials()
			return nil, err
		}
	}
	return handle, nil
}

// ConnectAuthorityFixture restores the pre-enrolled lane credential and logs in
// using only the handle's trust and loopback-forwarded admin endpoint. It clears
// transferred secrets even on failure. The connected fixture cannot configure,
// restart or wait for the controller; Close clears only its local credentials.
// OwnerSession instances remain caller-owned and must be closed.
func ConnectAuthorityFixture(ctx context.Context, handle *ControlPlaneHandle) (_ *AuthorityFixture, resultErr error) {
	return connectAuthorityFixture(ctx, handle, "", true)
}

func connectAuthorityFixture(ctx context.Context, handle *ControlPlaneHandle, stateDir string, fresh bool) (_ *AuthorityFixture, resultErr error) {
	if handle == nil {
		return nil, errors.New("connect authority requires a control-plane handle")
	}
	defer handle.ClearCredentials()
	if handle.AdminPort == 0 || handle.ConsoleOrigin != fmt.Sprintf("https://localhost:%d", handle.AdminPort) {
		return nil, errors.New("control-plane handle requires matching localhost HTTPS origin and admin port")
	}
	id, err := uuid.Parse(handle.AccountID)
	if err != nil || id == uuid.Nil || strings.TrimSpace(handle.Username) == "" || len(handle.Password) == 0 || handle.WebAuthnCounter == 0 || handle.WebAuthnCounter == ^uint32(0) || handle.DatabaseName == "" {
		return nil, errors.New("control-plane handle requires an enrolled account credential and database identity")
	}
	tlsConfig, err := trustClientPEM(handle.TransportCAPEM)
	if err != nil {
		return nil, fmt.Errorf("trust connected authority: %w", err)
	}
	f := &AuthorityFixture{
		AdminAddress:  net.JoinHostPort("127.0.0.1", strconv.Itoa(int(handle.AdminPort))),
		ConsoleOrigin: handle.ConsoleOrigin, DeviceOrigin: handle.DeviceOrigin, DatabaseName: handle.DatabaseName,
		connected: &connectedAuthority{tls: tlsConfig, material: AgentFixture{
			ExecutionRootJSON: bytes.Clone(handle.ExecutionRootJSON), BootstrapEnvelope: bytes.Clone(handle.BootstrapEnvelope),
		}},
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, f.Close())
		}
	}()
	if _, err := f.connectedAgentFixture(ctx); err != nil {
		return nil, fmt.Errorf("verify connected agent fixture: %w", err)
	}
	authenticator, err := webauthnlab.Import("localhost", handle.WebAuthnCredentialID, handle.WebAuthnPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("restore connected owner credential: %w", err)
	}
	f.local = &localAuthority{owner: &localAccount{
		id: id.String(), username: handle.Username, password: bytes.Clone(handle.Password),
		authenticator: authenticator, counter: handle.WebAuthnCounter,
	}}
	if stateDir != "" {
		f.directory, f.persistent = stateDir, true
		f.local.owner.statePath = filepath.Join(stateDir, "owner.json")
		if err := f.local.owner.persist(); err != nil {
			return nil, err
		}
	}
	setup, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	session, err := f.OpenOwnerSession(setup)
	if err != nil {
		return nil, fmt.Errorf("log in connected authority owner: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, closeReleaseSession(session)) }()
	// Independent approval authority is needed for remote lane device cleanup.
	// This new enrollment is issued by the remote owner, never copied from the
	// controller's private owner or approver credentials.
	if !fresh {
		f.local.approver, err = restorePersistentAccount(filepath.Join(stateDir, "approver.json"))
		if err != nil {
			return nil, err
		}
	} else if err := f.enrollLocalApprover(setup, session, "remote-approver-"+uuid.NewString()); err != nil {
		return nil, fmt.Errorf("enroll connected authority approver: %w", err)
	}
	if stateDir != "" {
		if err := f.persistLocalAccounts(); err != nil {
			return nil, err
		}
	}
	return f, nil
}

// Disable lane accounts through the same authorization/session revocation path
// as ordinary account administration, while the controller is still serving.
func (f *AuthorityFixture) disableExportedAccounts() (resultErr error) {
	if len(f.exportedAccounts) == 0 {
		return nil
	}
	ids := f.exportedAccounts
	f.exportedAccounts = nil
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	owner, err := f.OpenOwnerSession(ctx)
	if err != nil {
		return fmt.Errorf("open controller session to disable exported accounts: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, closeReleaseSession(owner)) }()
	for _, id := range ids {
		err := owner.localRequest(ctx, "/auth/accounts/update", &authv1.UpdateAccountRequest{AccountId: id, Enabled: false, Role: "owner"}, nil, http.StatusNoContent)
		if err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("disable exported lane account: %w", err))
		}
	}
	return resultErr
}

func (f *AuthorityFixture) localTLSConfig() (*tls.Config, error) {
	if f.connected != nil {
		return f.connected.tls.Clone(), nil
	}
	return trustClient(f.transportTrustDirectory())
}

func (f *AuthorityFixture) connectedDialContext() func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	originAddress := strings.TrimPrefix(f.ConsoleOrigin, "https://")
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != originAddress {
			return nil, errors.New("connected authority may dial only its forwarded admin origin")
		}
		return dialer.DialContext(ctx, "tcp4", f.AdminAddress)
	}
}

func (f *AuthorityFixture) connectedAgentFixture(ctx context.Context) (*AgentFixture, error) {
	if f.closed {
		return nil, errors.New("connected authority fixture is closed")
	}
	authority, err := trust.New()
	if err != nil {
		return nil, err
	}
	material := &f.connected.material
	verified, err := authority.VerifyBootstrap(ctx, material.ExecutionRootJSON, material.BootstrapEnvelope, time.Now())
	if err != nil {
		return nil, err
	}
	if verified.Bundle.GetDeviceOrigin() != f.DeviceOrigin || verified.Bundle.GetEnrollmentOrigin() != f.ConsoleOrigin {
		return nil, errors.New("control-plane handle origins differ from signed bootstrap")
	}
	return &AgentFixture{ExecutionRootJSON: bytes.Clone(material.ExecutionRootJSON), BootstrapEnvelope: bytes.Clone(material.BootstrapEnvelope)}, nil
}
