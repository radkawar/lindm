package devlab

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/html"
	"google.golang.org/protobuf/encoding/protojson"

	"lindm/gen/lindm/admin/v1/adminv1connect"
	authv1 "lindm/gen/lindm/auth/v1"
)

type brokerBrowser struct {
	client    *http.Client
	origin    string
	principal *authv1.SessionPrincipal
	admin     adminv1connect.AdminServiceClient
}

func brokerBrowserURL(endpoint *url.URL, origin string) bool {
	if endpoint == nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.Fragment != "" {
		return false
	}
	if endpoint.Scheme+"://"+endpoint.Host == origin {
		return endpoint.Path == "/" || endpoint.Path == "/auth/login" || endpoint.Path == "/auth/callback" || endpoint.Path == "/auth/session"
	}
	return endpoint.Host == "localhost:18443" && (strings.HasPrefix(endpoint.Path, "/realms/"+brokerRealm+"/") || strings.HasPrefix(endpoint.Path, "/realms/"+brokerUpstreamRealm+"/"))
}

// brokerForm accepts exactly one POST form and only the two owned SAML endpoints
// or the upstream password endpoint. It does not execute arbitrary HTML/scripts.
func brokerForm(body []byte, base *url.URL) (*url.URL, url.Values, string, error) {
	document, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, nil, "", err
	}
	var form *html.Node
	var walk func(*html.Node) error
	walk = func(node *html.Node) error {
		if node.Type == html.ElementNode && node.Data == "form" {
			if form != nil {
				return errors.New("ambiguous broker login forms")
			}
			form = node
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			if err := walk(child); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(document); err != nil {
		return nil, nil, "", err
	}
	if form == nil || !strings.EqualFold(htmlAttribute(form, "method"), "post") {
		return nil, nil, "", errors.New("missing broker POST form")
	}
	action, err := base.Parse(htmlAttribute(form, "action"))
	if err != nil || action.Scheme != "https" || action.Host != "localhost:18443" || action.User != nil || action.Fragment != "" {
		return nil, nil, "", errors.New("untrusted broker form destination")
	}
	values := make(url.Values)
	walk = func(node *html.Node) error {
		if node.Type == html.ElementNode && node.Data == "input" && strings.EqualFold(htmlAttribute(node, "type"), "hidden") {
			name := htmlAttribute(node, "name")
			if name != "" {
				values.Add(name, htmlAttribute(node, "value"))
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			if err := walk(child); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(form); err != nil {
		return nil, nil, "", err
	}
	switch {
	case action.Path == "/realms/"+brokerUpstreamRealm+"/protocol/saml" && len(values["SAMLRequest"]) == 1 && values.Get("SAMLRequest") != "":
		return action, values, "request", nil
	case action.Path == "/realms/"+brokerRealm+"/broker/"+brokerAlias+"/endpoint" && len(values["SAMLResponse"]) == 1 && values.Get("SAMLResponse") != "":
		return action, values, "response", nil
	case htmlAttribute(form, "id") == "kc-form-login" && action.Path == "/realms/"+brokerUpstreamRealm+"/login-actions/authenticate" && action.Query().Get("client_id") == brokerSAMLClient:
		return action, values, "password", nil
	default:
		return nil, nil, "", errors.New("broker form does not target an owned SAML or credential endpoint")
	}
}

func openBrokerBrowser(ctx context.Context, transport *http.Transport, origin, clientID, username, password string) (*brokerBrowser, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Transport: transport, Jar: jar, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	browser := &brokerBrowser{client: client, origin: origin}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/auth/login", nil)
	if err != nil {
		return nil, err
	}
	pkce, samlRequest, samlResponse, credential := false, false, false, false
	for range 16 {
		resp, err := client.Do(req)
		if err != nil {
			return nil, errors.New("owned broker browser request failed")
		}
		body, readErr := readFixtureResponse(resp)
		err = errors.Join(readErr, resp.Body.Close())
		if err != nil {
			clear(body)
			return nil, err
		}
		if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther {
			target, err := resp.Location()
			clear(body)
			if err != nil || !brokerBrowserURL(target, origin) {
				return nil, errors.New("broker login redirect escaped owned origins")
			}
			if target.Path == "/realms/"+brokerRealm+"/protocol/openid-connect/auth" {
				query := target.Query()
				if pkce || query.Get("client_id") != clientID || query.Get("response_type") != "code" || query.Get("code_challenge_method") != "S256" || len(query.Get("code_challenge")) != 43 || query.Get("redirect_uri") != origin+"/auth/callback" || query.Get("state") == "" || query.Get("nonce") == "" {
					return nil, errors.New("broker login did not use exact code/PKCE redirect")
				}
				pkce = true
				query.Set("kc_idp_hint", brokerAlias)
				target.RawQuery = query.Encode()
			}
			if target.String() == origin+"/" {
				if !pkce || !samlRequest || !samlResponse || !credential {
					return nil, errors.New("broker login did not complete a real upstream SAML password flow")
				}
				status, principal, err := browser.session(ctx)
				if err != nil {
					return nil, err
				}
				if status != http.StatusOK || principal.GetIssuer() != brokerIssuer || principal.GetRole() != "admin" || principal.GetCsrfToken() == "" {
					return nil, errors.New("broker session did not bind expected application authority")
				}
				browser.principal = principal
				browser.admin = adminv1connect.NewAdminServiceClient(client, origin, connect.WithInterceptors(connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
					return func(ctx context.Context, request connect.AnyRequest) (connect.AnyResponse, error) {
						request.Header().Set("Origin", origin)
						request.Header().Set("X-CSRF-Token", principal.GetCsrfToken())
						return next(ctx, request)
					}
				})))
				return browser, nil
			}
			req, err = http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
			if err != nil {
				return nil, err
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			clear(body)
			return nil, fmt.Errorf("broker browser flow rejected (HTTP %d)", resp.StatusCode)
		}
		action, form, kind, err := brokerForm(body, resp.Request.URL)
		clear(body)
		if err != nil {
			return nil, err
		}
		switch kind {
		case "request":
			if samlRequest {
				return nil, errors.New("repeated SAML request")
			}
			samlRequest = true
		case "response":
			if samlResponse || !credential {
				return nil, errors.New("unexpected SAML response")
			}
			samlResponse = true
		case "password":
			if credential || !samlRequest {
				return nil, errors.New("unexpected upstream credential request")
			}
			credential = true
			form.Set("username", username)
			form.Set("password", password)
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, action.String(), strings.NewReader(form.Encode()))
		form.Del("password")
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "https://localhost:18443")
	}
	return nil, errors.New("broker browser redirect/form bound exceeded")
}

func (b *brokerBrowser) session(ctx context.Context) (int, *authv1.SessionPrincipal, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.origin+"/auth/session", nil)
	if err != nil {
		return 0, nil, err
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return 0, nil, errors.New("read active broker session failed")
	}
	body, readErr := readFixtureResponse(resp)
	err = errors.Join(readErr, resp.Body.Close())
	if err != nil {
		return 0, nil, err
	}
	principal := new(authv1.SessionPrincipal)
	if resp.StatusCode == http.StatusOK {
		if err := protojson.Unmarshal(body, principal); err != nil {
			return 0, nil, err
		}
	}
	return resp.StatusCode, principal, nil
}
