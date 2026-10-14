// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	configv1 "lindm/gen/lindm/config/v1"
)

// EntraEvidence contains no passwords, client secrets, tokens or browser material.
type EntraEvidence struct {
	Prefix          string             `json:"prefix"`
	Started         time.Time          `json:"started"`
	Finished        time.Time          `json:"finished"`
	Tenant          string             `json:"tenant,omitempty"`
	Origin          string             `json:"origin,omitempty"`
	OwnerLogin      bool               `json:"owner_login"`
	AdminLogin      bool               `json:"admin_login"`
	Measurements    []EntraMeasurement `json:"measurements,omitempty"`
	CleanupComplete bool               `json:"cleanup_complete"`
	BrowserMode     string             `json:"browser_mode,omitempty"`
	Passed          bool               `json:"passed"`
	Failure         string             `json:"failure,omitempty"`
}

type EntraMeasurement struct {
	Stage                   string    `json:"stage"`
	Mutation                time.Time `json:"mutation"`
	GraphVisible            time.Time `json:"graph_visible"`
	Denied                  time.Time `json:"denied"`
	PropagationMilliseconds int64     `json:"propagation_ms"`
	EnforcementMilliseconds int64     `json:"enforcement_ms"`
	SessionHTTP             int       `json:"session_http"`
}

// CheckEntraAuthorization owns a live tenant's explicitly named test objects and
// an isolated real server. It never resets the development environment.
func CheckEntraAuthorization(ctx context.Context, repository, binary, cleanupPrefix string, unsandboxedBrowser bool) (result EntraEvidence, resultErr error) {
	result.Started = time.Now().UTC()
	defer func() {
		result.Finished = time.Now().UTC()
		result.Passed = resultErr == nil && cleanupPrefix == ""
		if resultErr != nil {
			result.Failure = resultErr.Error()
		}
	}()
	if cleanupPrefix != "" {
		result.Prefix = cleanupPrefix
		resultErr = cleanupEntra(ctx, cleanupPrefix)
		result.CleanupComplete = resultErr == nil
		return
	}
	result.BrowserMode = "sandboxed Chromium"
	if unsandboxedBrowser {
		result.BrowserMode = "no-sandbox lab browser"
	}
	root, err := filepath.Abs(repository)
	if err != nil {
		return result, err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	result.Prefix = "lindm-entra-check-" + uuid.NewString()
	directory, err := os.MkdirTemp("", "lindm-entra-run-")
	if err != nil {
		return result, err
	}
	defer func() {
		cleanupErr := os.RemoveAll(directory)
		result.CleanupComplete = result.CleanupComplete && cleanupErr == nil
		resultErr = errors.Join(resultErr, cleanupErr)
	}()
	result.CleanupComplete = true // No tenant objects exist before browser preflight.
	if err := checkEntraChromium(ctx, directory, unsandboxedBrowser); err != nil {
		return result, err
	}
	var tenant *entraTenant
	// Successful provisioning retains exact created IDs and its pinned tenant;
	// partial failure cleanup also discovers a lost create response by full prefix.
	defer func() {
		var cleanupErr error
		if tenant != nil {
			cleanupErr = tenant.cleanup(context.WithoutCancel(ctx))
		} else {
			cleanupErr = cleanupEntra(context.WithoutCancel(ctx), result.Prefix)
		}
		result.CleanupComplete = result.CleanupComplete && cleanupErr == nil
		resultErr = errors.Join(resultErr, cleanupErr)
	}()
	tenant, err = provisionEntra(ctx, directory, result.Prefix)
	if err != nil {
		return result, err
	}
	result.Tenant = tenant.tenant
	proxy, err := openEntraGraphProxy()
	if err != nil {
		return result, err
	}
	defer func() {
		cleanupErr := proxy.close()
		result.CleanupComplete = result.CleanupComplete && cleanupErr == nil
		resultErr = errors.Join(resultErr, cleanupErr)
	}()
	fixture, origin, err := openDirectoryServer(ctx, root, binary, directoryServerOptions{
		authentication: &configv1.AuthenticationConfig{Primary: &configv1.AuthenticationConfig_Entra{Entra: &configv1.EntraDirectory{TenantId: tenant.tenant, ClientId: tenant.loginID, ClientSecretFile: "entra-login-secret", DirectoryClientId: tenant.directoryID, DirectoryClientSecretFile: "entra-directory-secret"}}},
		group:          tenant.group, secrets: map[string]string{"entra-login-secret": tenant.loginSecret, "entra-directory-secret": tenant.directorySecret},
		register:  func(origin string) error { return tenant.redirect(ctx, origin) },
		bootstrap: []string{"-tenant-id", tenant.tenant, "-object-id", tenant.ownerID}, environment: proxy.environment(),
		parentDirectory: directory,
	})
	if err != nil {
		return result, err
	}
	defer func() {
		cleanupErr := fixture.Close()
		result.CleanupComplete = result.CleanupComplete && cleanupErr == nil
		resultErr = errors.Join(resultErr, cleanupErr)
	}()
	result.Origin = origin
	ownerMFA, adminMFA := new(entraMFA), new(entraMFA)
	owner, err := openEntraBrowser(ctx, root, directory, origin, tenant.ownerUPN, tenant.ownerPassword, unsandboxedBrowser, ownerMFA)
	if err != nil {
		return result, fmt.Errorf("owner authorization-code login: %w", err)
	}
	defer owner.client.CloseIdleConnections()
	if err := entraInitialAuthority(ctx, owner, tenant.ownerID, "owner"); err != nil {
		return result, err
	}
	result.OwnerLogin = true
	admin, err := openEntraBrowser(ctx, root, directory, origin, tenant.adminUPN, tenant.adminPassword, unsandboxedBrowser, adminMFA)
	if err != nil {
		return result, fmt.Errorf("admin authorization-code login: %w", err)
	}
	defer admin.client.CloseIdleConnections()
	if err := entraInitialAuthority(ctx, admin, tenant.adminID, "admin"); err != nil {
		return result, err
	}
	result.AdminLogin = true
	mutation := time.Now().UTC()
	if err := tenant.membership(ctx, false); err != nil {
		return result, err
	}
	measured, err := measureEntraDenial(ctx, tenant, admin, "group-removal", mutation)
	result.Measurements = append(result.Measurements, measured)
	if err != nil {
		return result, err
	}
	if err := tenant.membership(ctx, true); err != nil {
		return result, err
	}
	if err := awaitEntraMembership(ctx, tenant); err != nil {
		return result, err
	}
	// A new session is allowed only BETWEEN scenarios, never after their mutation.
	admin, err = openEntraBrowser(ctx, root, directory, origin, tenant.adminUPN, tenant.adminPassword, unsandboxedBrowser, adminMFA)
	if err != nil {
		return result, err
	}
	defer admin.client.CloseIdleConnections()
	if err := entraInitialAuthority(ctx, admin, tenant.adminID, "admin"); err != nil {
		return result, err
	}
	mutation = time.Now().UTC()
	if err := tenant.enabled(ctx, false); err != nil {
		return result, err
	}
	measured, err = measureEntraDenial(ctx, tenant, admin, "disable", mutation)
	result.Measurements = append(result.Measurements, measured)
	if err != nil {
		return result, err
	}
	// Preserve the ORIGINAL owner's session for outage, proving existing-session
	// fail-closed even for the bootstrapped owner rather than merely mapped admins.
	if err := entraInitialAuthority(ctx, owner, tenant.ownerID, "owner"); err != nil {
		return result, err
	}
	mutation = time.Now().UTC()
	if err := proxy.fail(); err != nil {
		return result, err
	}
	measured, err = measureEntraDenial(ctx, tenant, owner, "graph-outage", mutation)
	result.Measurements = append(result.Measurements, measured)
	return result, err
}

func entraInitialAuthority(ctx context.Context, b *brokerBrowser, subject, role string) error {
	status, principal, err := b.session(ctx)
	if err != nil {
		return err
	}
	if status != http.StatusOK || principal.GetSubject() != subject || principal.GetRole() != role {
		return errors.New("entra: session did not bind expected immutable subject and role")
	}
	_, err = b.admin.ListDevices(ctx, connect.NewRequest(&adminv1.ListDevicesRequest{PageSize: 1}))
	return err
}

func awaitEntraMembership(ctx context.Context, t *entraTenant) error {
	deadline, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		visible, err := t.observe(deadline, false)
		if err != nil {
			return err
		}
		if visible {
			return nil
		}
		select {
		case <-deadline.Done():
			return errors.New("entra: Graph membership regrant propagation exceeded 3 minutes")
		case <-ticker.C:
		}
	}
}

func measureEntraDenial(ctx context.Context, t *entraTenant, b *brokerBrowser, stage string, mutation time.Time) (m EntraMeasurement, resultErr error) {
	m.Stage, m.Mutation = stage, mutation
	outage := stage == "graph-outage"
	if outage {
		m.GraphVisible = mutation
	}
	deadline, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if m.GraphVisible.IsZero() {
			observed, err := t.observe(deadline, stage == "disable")
			if err != nil {
				return m, err
			}
			if (stage == "disable" && observed) || (stage == "group-removal" && !observed) {
				m.GraphVisible = time.Now().UTC()
			}
		}
		probe := deadline
		stop := func() {}
		if !m.GraphVisible.IsZero() {
			probe, stop = context.WithDeadline(deadline, m.GraphVisible.Add(60*time.Second))
		}
		_, rpcErr := b.admin.ListDevices(probe, connect.NewRequest(&adminv1.ListDevicesRequest{PageSize: 1}))
		rpcDenied := connect.CodeOf(rpcErr) == connect.CodeUnauthenticated || connect.CodeOf(rpcErr) == connect.CodePermissionDenied || (outage && connect.CodeOf(rpcErr) == connect.CodeUnavailable)
		status, principal, err := b.session(probe)
		stop()
		if err != nil {
			return m, err
		}
		if rpcErr != nil && !rpcDenied {
			return m, fmt.Errorf("unexpected protected Entra RPC failure: %w", rpcErr)
		}
		sessionDenied := status == http.StatusUnauthorized || status == http.StatusForbidden || (outage && status == http.StatusServiceUnavailable)
		if stage == "group-removal" && status == http.StatusOK {
			sessionDenied = principal.GetRole() == "" && len(principal.GetPermissions()) == 0 && len(principal.GetBindings()) == 0
		}
		if sessionDenied && rpcDenied && m.Denied.IsZero() {
			m.Denied = time.Now().UTC()
			m.SessionHTTP = status
		}
		if !m.GraphVisible.IsZero() && !m.Denied.IsZero() {
			m.PropagationMilliseconds = m.GraphVisible.Sub(mutation).Milliseconds()
			m.EnforcementMilliseconds = m.Denied.Sub(m.GraphVisible).Milliseconds()
			if m.Denied.Sub(m.GraphVisible) >= 60*time.Second {
				return m, errors.New("entra: active-session denial exceeded 60 seconds after Graph visibility")
			}
			return m, nil
		}
		if !m.GraphVisible.IsZero() && time.Since(m.GraphVisible) >= 60*time.Second {
			return m, errors.New("entra: active-session authority survived 60-second freshness bound")
		}
		select {
		case <-deadline.Done():
			return m, errors.New("entra: propagation/enforcement deadline exceeded")
		case <-ticker.C:
		}
	}
}
