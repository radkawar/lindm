package ctl

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	adminv1connect "lindm/gen/lindm/admin/v1/adminv1connect"
	authv1 "lindm/gen/lindm/auth/v1"
)

// Client owns a pinned server connection and protected credential store. Close it
// after use. Login and Logout serialize credential changes.
type Client struct {
	mu        sync.Mutex
	config    *authv1.CLIConfig
	store     *configStore
	http      *http.Client
	origin    string
	transport *http.Transport
	rules     protovalidate.Validator
	admin     adminv1connect.AdminServiceClient
}

// New loads a private config or pins the supplied first-use configuration. A
// supplied configuration cannot replace an existing origin, CA, or session.
func New(configPath string, config *authv1.CLIConfig) (_ *Client, resultErr error) {
	if configPath == "" {
		return nil, errors.New("CLI configuration path is required")
	}
	rules, err := protovalidate.New(protovalidate.WithMessages(
		&authv1.CLIConfig{}, &authv1.CLIExchangeRequest{}, &authv1.CLIExchangeResponse{},
		&adminv1.ListDevicesRequest{}, &adminv1.GetDeviceRequest{}, &adminv1.RevokeDeviceRequest{},
		&adminv1.CreateEnrollmentGrantRequest{}, &adminv1.RevokeEnrollmentGrantRequest{},
		&adminv1.ListProfilesRequest{}, &adminv1.GetProfileRevisionRequest{},
		&adminv1.PublishProfileRevisionRequest{}, &adminv1.SetResourceAssignmentRequest{},
		&adminv1.GetDeviceResourceStateRequest{}, &adminv1.ListAuditEventsRequest{},
	))
	if err != nil {
		return nil, fmt.Errorf("compile CLI schema rules: %w", err)
	}
	store, err := openStore(configPath)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, store.dir.Close())
		}
	}()
	persisted, err := store.load()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if persisted != nil {
		if config != nil && !samePin(config, persisted) {
			return nil, errors.New("refusing to replace pinned server origin or CA")
		}
		config = persisted
	}
	if config == nil {
		return nil, errors.New("not configured: login requires --server and --ca")
	}
	config = proto.CloneOf(config)
	if err := rules.Validate(config); err != nil {
		return nil, errors.New("CLI configuration violates schema rules")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(config.GetCaPem())) {
		return nil, errors.New("pinned CA contains no usable certificates")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
	c := &Client{config: config, store: store, rules: rules, transport: transport, origin: strings.TrimSuffix(config.GetServerOrigin(), "/")}
	c.http = &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	c.admin = adminv1connect.NewAdminServiceClient(c.http, config.GetServerOrigin(), connect.WithReadMaxBytes(maxDocumentBytes), connect.WithInterceptors(connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			message, ok := req.Any().(proto.Message)
			if !ok {
				return nil, errors.New("RPC request is not a protobuf message")
			}
			if err := c.rules.Validate(message); err != nil {
				return nil, errors.New("RPC request violates schema rules")
			}
			c.mu.Lock()
			token := c.config.GetSessionToken()
			c.mu.Unlock()
			if token == "" {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("login required"))
			}
			req.Header().Set("Authorization", "Bearer "+token)
			ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			response, err := next(ctx, req)
			if err != nil {
				return nil, connect.NewError(connect.CodeOf(err), errors.New("administrative RPC failed"))
			}
			return response, nil
		}
	})))
	return c, nil
}

// Admin exposes the generated RPC client with validation, bearer authentication,
// bounded calls, and redirect refusal already installed.
func (c *Client) Admin() adminv1connect.AdminServiceClient { return c.admin }

// Close releases the private directory descriptor and idle connections.
func (c *Client) Close() error {
	c.transport.CloseIdleConnections()
	return c.store.dir.Close()
}

// HTTPError reports status without echoing untrusted bodies or credential data.
type HTTPError struct{ StatusCode int }

func (e *HTTPError) Error() string {
	return fmt.Sprintf("authentication request failed (HTTP %d)", e.StatusCode)
}

func (c *Client) authRequest(ctx context.Context, method, path, token string, input, output proto.Message) (resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var body io.Reader
	if input != nil {
		if err := c.rules.Validate(input); err != nil {
			return errors.New("authentication request violates schema rules")
		}
		data, err := protojson.Marshal(input)
		if err != nil {
			return errors.New("encode authentication request")
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.origin+path, body)
	if err != nil {
		return errors.New("create authentication request")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return errors.New("authentication transport failed")
	}
	defer func() { resultErr = errors.Join(resultErr, resp.Body.Close()) }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &HTTPError{StatusCode: resp.StatusCode}
	}
	if output == nil {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDocumentBytes+1))
	if err != nil {
		return errors.New("read authentication response")
	}
	if len(data) > maxDocumentBytes {
		return errors.New("authentication response exceeds document limit")
	}
	if err := protojson.Unmarshal(data, output); err != nil {
		return errors.New("invalid authentication response")
	}
	if err := c.rules.Validate(output); err != nil {
		return errors.New("authentication response violates schema rules")
	}
	return nil
}

// Whoami returns the current server-authorized session, never the bearer token.
func (c *Client) Whoami(ctx context.Context) (*authv1.SessionPrincipal, error) {
	c.mu.Lock()
	token := c.config.GetSessionToken()
	c.mu.Unlock()
	if token == "" {
		return nil, errors.New("login required")
	}
	principal := &authv1.SessionPrincipal{}
	if err := c.authRequest(ctx, http.MethodGet, "/auth/session", token, nil, principal); err != nil {
		return nil, err
	}
	return principal, nil
}

// Logout revokes the server session before clearing the durable local token.
func (c *Client) Logout(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.config.GetSessionToken() == "" {
		return nil
	}
	err := c.authRequest(ctx, http.MethodPost, "/auth/logout", c.config.GetSessionToken(), nil, nil)
	var status *HTTPError
	if err != nil && (!errors.As(err, &status) || status.StatusCode != http.StatusUnauthorized) {
		return err
	}
	cfg := proto.CloneOf(c.config)
	cfg.SessionToken = ""
	if err := c.store.save(cfg); err != nil {
		return err
	}
	c.config = cfg
	return nil
}

func randomToken() (string, error) {
	var data [32]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", errors.New("generate cryptographic token")
	}
	return base64.RawURLEncoding.EncodeToString(data[:]), nil
}
