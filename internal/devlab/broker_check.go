package devlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/config"
)

// CheckBrokerAuthorization uses only protected maintained lab inputs, a prebuilt
// lindmd, an owned database, and UUID-prefixed objects in the dedicated SAML realms.
// No active-session mutation stage performs a second SAML login.
func CheckBrokerAuthorization(ctx context.Context, repository, binary, cleanupPrefix string, evidence io.Writer) error {
	root, err := filepath.Abs(repository)
	if err != nil {
		return err
	}
	// ReadPublicAgentFixture owns its short fixture-read lock. Holding that
	// lock across the whole lane would deadlock its nested read and block
	// unrelated isolated fixtures; resets are operator-coordinated.
	return checkBrokerAuthorization(ctx, root, binary, cleanupPrefix, evidence)
}

func checkBrokerAuthorization(ctx context.Context, root, binary, cleanupPrefix string, evidence io.Writer) (resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	secrets, err := brokerInputs(root)
	if err != nil {
		return err
	}
	tlsConfig, err := trustClient(FixturePath(root))
	if err != nil {
		return err
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, MaxIdleConns: 8, MaxIdleConnsPerHost: 4, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 10 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	upstream := &brokerRealmAdmin{client: client, realm: brokerUpstreamRealm, secret: secrets["broker-upstream-admin-secret"]}
	broker := &brokerRealmAdmin{client: client, realm: brokerRealm, secret: secrets["broker-admin-secret"]}
	admins := []*brokerRealmAdmin{broker, upstream}
	if cleanupPrefix != "" {
		return cleanupBrokerOwned(ctx, admins, cleanupPrefix, evidence)
	}
	if binary == "" {
		return errors.New("broker check requires -lindmd FILE, or -cleanup-prefix lindm-broker-check-UUID")
	}
	prefix := brokerOwnedPrefix + uuid.NewString()
	if _, err := fmt.Fprintf(evidence, "broker owned prefix=%s realms=%s,%s; cleanup: lab auth check-broker -repo %s -cleanup-prefix %s\n", prefix, brokerUpstreamRealm, brokerRealm, root, prefix); err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, cleanupBrokerOwned(ctx, admins, prefix, evidence)) }()
	for _, admin := range admins {
		if err := admin.authenticate(ctx); err != nil {
			return err
		}
	}
	group := prefix + "-grant"
	upstreamGroup, err := upstream.create(ctx, "groups", map[string]any{"name": group})
	if err != nil {
		return err
	}
	brokerGroup, err := broker.create(ctx, "groups", map[string]any{"name": group})
	if err != nil {
		return err
	}
	proxy, err := openBrokerUpstreamProxy(FixturePath(root), transport)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, proxy.close()) }()
	clientSecret := uuid.NewString() + uuid.NewString()
	fixture, origin, err := openBrokerServer(ctx, root, binary, prefix, clientSecret, group, proxy.issuer, func(origin string) error {
		_, err := broker.create(ctx, "clients", brokerClient(prefix, clientSecret, origin))
		return err
	})
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, fixture.Close()) }()
	if _, err := fmt.Fprintf(evidence, "broker isolated origin=%s database=%s exact-owned-client=%s source=real-upstream-admin-api-via-owned-TLS-fault-proxy\n", origin, fixture.DatabaseName, prefix); err != nil {
		return err
	}
	type actor struct {
		name, upstreamID, brokerID string
		browser                    *brokerBrowser
	}
	actors := make([]actor, 0, 3)
	for _, stage := range []string{"group-removal", "disable", "upstream-outage"} {
		name, password := prefix+"-"+stage, uuid.NewString()+uuid.NewString()
		email := uuid.NewString() + "@lindm.example"
		userID, err := upstream.create(ctx, "users", map[string]any{"username": name, "enabled": true, "firstName": "Owned", "lastName": "Upstream",
			"email": email, "emailVerified": true, "requiredActions": []string{},
			"credentials": []any{map[string]any{"type": "password", "value": password, "temporary": false}}})
		if err != nil {
			return err
		}
		// The lab-admin binds a persistent SAML NameID to the provider's immutable
		// ID, never username/email. Only admin can edit unmanaged attributes.
		_, _, err = upstream.request(ctx, http.MethodPut, "/users/"+userID, map[string]any{"attributes": map[string][]string{"saml.persistent.name.id.for." + brokerSAMLClient: {userID}}}, http.StatusNoContent)
		if err != nil {
			return err
		}
		if err := upstream.membership(ctx, userID, upstreamGroup, true); err != nil {
			return err
		}
		brokerID, err := broker.create(ctx, "users", map[string]any{"username": name, "enabled": true, "firstName": "Owned", "lastName": "Broker", "email": email, "emailVerified": true})
		if err != nil {
			return err
		}
		_, _, err = broker.request(ctx, http.MethodPost, "/users/"+brokerID+"/federated-identity/"+brokerAlias,
			map[string]string{"identityProvider": brokerAlias, "userId": userID, "userName": name}, http.StatusNoContent)
		if err != nil {
			return err
		}
		if err := broker.membership(ctx, brokerID, brokerGroup, true); err != nil {
			return err
		}
		browser, err := openBrokerBrowser(ctx, transport, origin, prefix, name, password)
		if err != nil {
			return fmt.Errorf("broker %s initial SAML login: %w", stage, err)
		}
		if browser.principal.GetSubject() != brokerID {
			return errors.New("broker login changed the immutable broker subject")
		}
		if _, err := browser.admin.ListDevices(ctx, connect.NewRequest(&adminv1.ListDevicesRequest{PageSize: 1})); err != nil {
			return fmt.Errorf("broker initial protected admin read: %w", err)
		}
		if err := verifyBrokerLineage(ctx, fixture, browser.principal.GetId(), brokerID, userID, proxy.issuer); err != nil {
			return err
		}
		actors = append(actors, actor{name: stage, upstreamID: userID, brokerID: brokerID, browser: browser})
	}
	if _, err := fmt.Fprintln(evidence, "broker signed persistent SAML -> signed OIDC PKCE logins=3; complete durable lineage and protected admin reads accepted; no further SAML logins"); err != nil {
		return err
	}
	for _, actor := range actors {
		mutation := time.Now()
		switch actor.name {
		case "group-removal":
			if err := upstream.membership(ctx, actor.upstreamID, upstreamGroup, false); err != nil {
				return err
			}
		case "disable":
			if _, _, err := upstream.request(ctx, http.MethodPut, "/users/"+actor.upstreamID, map[string]bool{"enabled": false}, http.StatusNoContent); err != nil {
				return err
			}
		case "upstream-outage":
			// Refresh immediately before the fault, then leave the imported broker
			// grant healthy. No changes to a shared connector/client are necessary.
			status, _, err := actor.browser.session(ctx)
			if err != nil || status != http.StatusOK {
				return errors.Join(err, errors.New("pre-outage active session was not healthy"))
			}
			proxy.failed.Store(true)
		}
		visible := time.Now()
		if actor.name != "upstream-outage" {
			visible, err = awaitBrokerUpstreamVisibility(ctx, upstream, actor.upstreamID, upstreamGroup, actor.name == "disable")
			if err != nil {
				return err
			}
		}
		_, userBody, err := broker.request(ctx, http.MethodGet, "/users/"+actor.brokerID, nil, http.StatusOK)
		if err != nil {
			return err
		}
		var brokerUser struct {
			Enabled bool `json:"enabled"`
		}
		if json.Unmarshal(userBody, &brokerUser) != nil || !brokerUser.Enabled {
			return errors.New("broker imported user was not healthy during upstream mutation")
		}
		_, body, err := broker.request(ctx, http.MethodGet, "/users/"+actor.brokerID+"/groups?max=100", nil, http.StatusOK)
		if err != nil {
			return err
		}
		var groups []struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(body, &groups) != nil {
			return errors.New("invalid healthy broker groups response")
		}
		found := false
		for _, g := range groups {
			if g.ID == brokerGroup {
				found = true
			}
		}
		if !found {
			return errors.New("broker imported grant was not healthy during upstream lifecycle mutation")
		}
		elapsed, status, err := awaitBrokerDenial(ctx, actor.browser, visible, actor.name)
		if err != nil {
			return fmt.Errorf("broker %s: %w", actor.name, err)
		}
		if _, err := fmt.Fprintf(evidence, "broker %s mutation=%s upstream-visible=%s propagation=%s active-session-grants-and-admin-RPC-denied session-HTTP=%d enforcement=%s bound=60s broker-import=enabled-and-member additional-SAML-logins=0\n", actor.name, mutation.UTC().Format(time.RFC3339Nano), visible.UTC().Format(time.RFC3339Nano), visible.Sub(mutation).Round(time.Millisecond), status, elapsed.Round(time.Millisecond)); err != nil {
			return err
		}
	}
	return nil
}

func awaitBrokerDenial(ctx context.Context, browser *brokerBrowser, visible time.Time, stage string) (time.Duration, int, error) {
	outage := stage == "upstream-outage"
	deadline, cancel := context.WithDeadline(ctx, visible.Add(60*time.Second))
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		_, rpcErr := browser.admin.ListDevices(deadline, connect.NewRequest(&adminv1.ListDevicesRequest{PageSize: 1}))
		rpcDenied := connect.CodeOf(rpcErr) == connect.CodeUnauthenticated || connect.CodeOf(rpcErr) == connect.CodePermissionDenied || (outage && connect.CodeOf(rpcErr) == connect.CodeUnavailable)
		if rpcErr != nil && !rpcDenied {
			return time.Since(visible), 0, fmt.Errorf("unexpected protected broker RPC failure: %w", rpcErr)
		}
		status, principal, err := browser.session(deadline)
		if err != nil {
			return 0, status, err
		}
		elapsed := time.Since(visible)
		sessionDenied := status == http.StatusUnauthorized || status == http.StatusForbidden || (outage && status == http.StatusServiceUnavailable)
		// Removing the last mapped group removes grants, not the underlying
		// authenticated identity. Require both an empty current grant snapshot
		// and denial of the same protected RPC used before the mutation.
		if stage == "group-removal" && status == http.StatusOK && principal != nil {
			sessionDenied = principal.GetRole() == "" && len(principal.GetPermissions()) == 0 && len(principal.GetBindings()) == 0
		}
		if sessionDenied && rpcDenied {
			if elapsed >= 60*time.Second {
				return elapsed, status, errors.New("broker revocation exceeded freshness bound")
			}
			return elapsed, status, nil
		}
		if status != http.StatusOK && !sessionDenied {
			return elapsed, status, fmt.Errorf("unexpected active broker session HTTP %d", status)
		}
		select {
		case <-deadline.Done():
			return elapsed, status, errors.New("healthy broker import masked upstream denial for 60 seconds")
		case <-ticker.C:
		}
	}
}

func verifyBrokerLineage(ctx context.Context, fixture *AuthorityFixture, principal, brokerSubject, upstreamSubject, upstreamIssuer string) (resultErr error) {
	document, err := config.Load(fixture.configPath())
	if err != nil {
		return err
	}
	cfg, err := document.MigrationDatabase()
	if err != nil {
		return err
	}
	connection, err := pgx.ConnectConfig(ctx, cfg.ConnConfig)
	if err != nil {
		return err
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		resultErr = errors.Join(resultErr, connection.Close(closeCtx))
	}()
	var issuer, subject, provider, original, connector string
	var observed time.Time
	err = connection.QueryRow(ctx, `SELECT broker_issuer,broker_subject,upstream_provider,upstream_subject,directory_connector,upstream_observed_at FROM principal_lineage WHERE principal_id=$1`, principal).Scan(&issuer, &subject, &provider, &original, &connector, &observed)
	if err != nil {
		return err
	}
	if issuer != brokerIssuer || subject != brokerSubject || provider != upstreamIssuer || original != upstreamSubject || connector != "owned-broker-upstream" || observed.IsZero() {
		return errors.New("broker complete immutable lineage was not durably bound")
	}
	return nil
}

func awaitBrokerUpstreamVisibility(ctx context.Context, upstream *brokerRealmAdmin, user, group string, disabled bool) (time.Time, error) {
	deadline, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		path := "/users/" + user
		if !disabled {
			path += "/groups?max=100"
		}
		_, body, err := upstream.request(deadline, http.MethodGet, path, nil, http.StatusOK)
		if err != nil {
			return time.Time{}, err
		}
		visible := false
		if disabled {
			var observed struct {
				ID      string `json:"id"`
				Enabled bool   `json:"enabled"`
			}
			if json.Unmarshal(body, &observed) != nil || observed.ID != user {
				return time.Time{}, errors.New("invalid original upstream disable observation")
			}
			visible = !observed.Enabled
		} else {
			var groups []struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(body, &groups) != nil || len(groups) >= 100 {
				return time.Time{}, errors.New("invalid original upstream membership observation")
			}
			visible = true
			for _, observed := range groups {
				if observed.ID == group {
					visible = false
				}
			}
		}
		if visible {
			return time.Now(), nil
		}
		select {
		case <-deadline.Done():
			return time.Time{}, errors.New("original upstream propagation visibility deadline")
		case <-ticker.C:
		}
	}
}
