package devlab

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	entraGraphBase       = "https://graph.microsoft.com/v1.0/"
	entraGraphApp        = "00000003-0000-0000-c000-000000000000"
	entraOutputLimit     = 1 << 20
	entraAppPermission   = "Application.ReadWrite.All delegated permission and an applicable application-management role (for example Cloud Application Administrator)"
	entraUserPermission  = "User.ReadWrite.All delegated permission and User Administrator for these non-admin test users"
	entraGroupPermission = "Group.ReadWrite.All delegated permission and Groups Administrator for ordinary security groups"
	entraReadPermission  = "Directory.Read.All delegated permission and a supported directory-reading role"
)

type entraTenant struct {
	tenant, prefix, group, ownerID, adminID, ownerUPN, adminUPN, ownerPassword, adminPassword, loginID, loginSecret, directoryID, directorySecret string
	graph                                                                                                                                         entraGraph
	loginObject                                                                                                                                   string
	owned                                                                                                                                         []entraOwned
}

type entraGraph struct {
	runDir       string
	subscription string
}

type entraObject struct {
	ID                 string   `json:"id"`
	AppID              string   `json:"appId"`
	DisplayName        string   `json:"displayName"`
	Description        string   `json:"description"`
	Department         string   `json:"department"`
	MailNickname       string   `json:"mailNickname"`
	UserPrincipalName  string   `json:"userPrincipalName"`
	Tags               []string `json:"tags"`
	SecurityEnabled    bool     `json:"securityEnabled"`
	MailEnabled        bool     `json:"mailEnabled"`
	IsAssignableToRole bool     `json:"isAssignableToRole"`
}

type entraOwned struct {
	Collection string `json:"collection"`
	ID         string `json:"id"`
}

// Only this complete random run identifier can authorize fixture mutations.
func validEntraPrefix(prefix string) bool {
	const stem = "lindm-entra-check-"
	if !strings.HasPrefix(prefix, stem) {
		return false
	}
	id := strings.TrimPrefix(prefix, stem)
	parsed, err := uuid.Parse(id)
	return err == nil && parsed != uuid.Nil && parsed.String() == id && parsed.Version() == 4
}

func entraNames(prefix, collection string) []string {
	switch collection {
	case "applications", "servicePrincipals":
		return []string{prefix + "-login", prefix + "-directory"}
	case "users":
		return []string{prefix + "-owner", prefix + "-admin"}
	case "groups":
		return []string{prefix + "-admins"}
	default:
		return nil
	}
}

func entraOwns(prefix, collection string, object entraObject) bool {
	if !validEntraPrefix(prefix) || !entraUUID(object.ID) {
		return false
	}
	matched := false
	for _, name := range entraNames(prefix, collection) {
		matched = matched || object.DisplayName == name
	}
	if !matched {
		return false
	}
	switch collection {
	case "applications":
		return object.Description == prefix && entraUUID(object.AppID)
	case "servicePrincipals":
		for _, tag := range object.Tags {
			if tag == prefix && entraUUID(object.AppID) {
				return true
			}
		}
	case "users":
		local, domain, ok := strings.Cut(object.UserPrincipalName, "@")
		return ok && domain != "" && !strings.ContainsAny(domain, "/@\\ \t\r\n") && local == object.DisplayName && object.MailNickname == local && object.Department == prefix
	case "groups":
		return object.Description == prefix && object.MailNickname == object.DisplayName && object.SecurityEnabled && !object.MailEnabled && !object.IsAssignableToRole
	}
	return false
}

func entraUUID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

// Retain a bounded prefix, but consume all writes so a noisy child cannot cause
// an unbounded allocation or a blocked pipe. Overflow is always an error.
type entraCapture struct {
	data     []byte
	limit    int
	overflow bool
}

func (b *entraCapture) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.limit - len(b.data)
	if len(p) > remaining {
		b.overflow = true
		p = p[:remaining]
	}
	b.data = append(b.data, p...)
	return n, nil
}

// Never echo Graph messages, CLI stderr, subprocess arguments or response bodies:
// Graph and az can include passwords, client secrets, bearer tokens and PII.
// Only known Graph codes and numeric AADSTS codes cross the diagnostic boundary.
func entraErrorCode(raw []byte) string {
	codes := []string{"Authorization_RequestDenied", "Authentication_MissingOrMalformed", "InvalidAuthenticationToken", "Request_ResourceNotFound", "ResourceNotFound", "Request_BadRequest", "Request_UnsupportedQuery", "InvalidRequest", "InvalidRequestBadParameter", "PermissionGrantPolicyViolation", "TooManyRequests", "ServiceUnavailable", "Forbidden", "BadRequest"}
	for _, code := range codes {
		for _, form := range []string{`"code":"` + code + `"`, `"code": "` + code + `"`, "(" + code + ")"} {
			if bytes.Contains(raw, []byte(form)) {
				if code == "Request_BadRequest" || code == "BadRequest" || code == "InvalidRequest" {
					lower := strings.ToLower(string(raw))
					switch {
					case strings.Contains(lower, "does not reference a valid application"):
						return code + ":application_not_visible"
					case strings.Contains(lower, "does not exist") && (strings.Contains(lower, "client") || strings.Contains(lower, "principal")):
						return code + ":principal_not_visible"
					case strings.Contains(lower, "read-only") || strings.Contains(lower, "read only"):
						return code + ":read_only_property"
					case strings.Contains(lower, "already exists"):
						return code + ":object_already_exists"
					case strings.Contains(lower, "invalid value"):
						return code + ":invalid_property_value"
					}
				}
				return code
			}
		}
	}
	if code := entraAADSTS.Find(raw); code != nil {
		return string(code)
	}
	// Microsoft occasionally returns service-specific codes not in the common
	// Graph list. Preserve only the bounded code identifier, never error.message.
	if match := entraProviderCode.FindSubmatch(raw); match != nil {
		return string(match[1])
	}
	// az may render an empty HTTP error body as a status label rather than JSON.
	for _, status := range []string{"Not Found", "Forbidden", "Conflict", "Too Many Requests", "Bad Gateway", "Service Unavailable"} {
		if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("ERROR: "+status)) {
			return "HTTP_" + strings.ReplaceAll(status, " ", "_")
		}
	}
	return "unavailable"
}

var entraProviderCode = regexp.MustCompile(`"code"\s*:\s*"([A-Za-z][A-Za-z0-9_.]{0,95})"`)

type entraGraphError struct {
	operation, code, permission string
}

func (e *entraGraphError) Error() string {
	if e.code == "Authorization_RequestDenied" || e.code == "Forbidden" {
		return fmt.Sprintf("entra: %s failed (Graph code %s); requires %s; the current identity's effective permissions were not inferred", e.operation, e.code, e.permission)
	}
	return fmt.Sprintf("entra: %s failed (Graph code %s); operation prerequisites: %s; this response does not establish a missing permission", e.operation, e.code, e.permission)
}

func entraMissing(err error) bool {
	var failure *entraGraphError
	return errors.As(err, &failure) && (failure.code == "Request_ResourceNotFound" || failure.code == "ResourceNotFound" || failure.code == "Directory_ObjectNotFound")
}

func entraAZ(ctx context.Context, operation, permission string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "az", append(args, "--only-show-errors", "--output", "json")...)
	cmd.WaitDelay = time.Second
	stdout := entraCapture{limit: entraOutputLimit}
	stderr := entraCapture{limit: 64 << 10}
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("entra: %s: %w", operation, ctx.Err())
		}
		code := entraErrorCode(stderr.data)
		if code == "unavailable" {
			code = entraErrorCode(stdout.data)
		}
		return nil, &entraGraphError{operation, code, permission}
	}
	if stdout.overflow || stderr.overflow {
		return nil, fmt.Errorf("entra: %s: captured output exceeded safety limit", operation)
	}
	return stdout.data, nil
}

func entraAccount(ctx context.Context, runDir string) (entraGraph, string, error) {
	body, err := entraAZ(ctx, "read Azure account", "an az login in the intended public-cloud test tenant", "account", "show")
	if err != nil {
		return entraGraph{}, "", err
	}
	var account struct {
		TenantID    string `json:"tenantId"`
		ID          string `json:"id"`
		Environment string `json:"environmentName"`
	}
	if json.Unmarshal(body, &account) != nil || !entraUUID(account.TenantID) || !entraUUID(account.ID) || account.Environment != "AzureCloud" {
		return entraGraph{}, "", errors.New("entra: requires an AzureCloud account with canonical tenant and subscription IDs")
	}
	return entraGraph{runDir: runDir, subscription: account.ID}, account.TenantID, nil
}

func (g entraGraph) rest(ctx context.Context, operation, permission, method, target string, payload, result any) (err error) {
	if !strings.HasPrefix(target, entraGraphBase) {
		return errors.New("entra: rejected a non-public-Graph request")
	}
	args := []string{"rest", "--subscription", g.subscription, "--method", method, "--url", target, "--resource", "https://graph.microsoft.com/", "--headers", "ConsistencyLevel=eventual", "Content-Type=application/json", "Cache-Control=no-cache"}
	if payload != nil {
		body, encodeErr := json.Marshal(payload)
		if encodeErr != nil {
			return errors.New("entra: request encoding failed")
		}
		defer clear(body)
		file, fileErr := os.CreateTemp(g.runDir, ".entra-request-*")
		if fileErr != nil {
			return errors.New("entra: cannot create private request body")
		}
		defer func() {
			if removeErr := os.Remove(file.Name()); removeErr != nil {
				err = errors.Join(err, errors.New("entra: cannot remove private request body"))
			}
		}()
		_, writeErr := file.Write(body)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			return errors.New("entra: cannot write private request body")
		}
		args = append(args, "--body", "@"+file.Name())
	}
	// Newly created application/service-principal objects can be readable on
	// one Graph replica but absent from another write replica. Repeat only a
	// definitive dependency-not-found rejection, never an ambiguous mutation.
	propagation, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var body []byte
	for {
		body, err = entraAZ(propagation, operation, permission, args...)
		var rejected *entraGraphError
		repeatable := errors.As(err, &rejected) && (method == "POST" || method == "PATCH") &&
			(rejected.code == "Request_BadRequest:application_not_visible" || rejected.code == "InvalidRequest:principal_not_visible" || entraMissing(err))
		repeatable = repeatable || (method == "GET" && strings.HasPrefix(operation, "verify owned ") && entraMissing(err))
		if !repeatable {
			break
		}
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-propagation.Done():
			timer.Stop()
			return errors.Join(err, propagation.Err())
		case <-timer.C:
		}
	}
	if err != nil {
		return err
	}
	defer clear(body)
	if result != nil && json.Unmarshal(body, result) != nil {
		return fmt.Errorf("entra: %s: malformed Graph response", operation)
	}
	return nil
}

func entraSelect(collection string) string {
	switch collection {
	case "applications":
		return "id,appId,displayName,description"
	case "servicePrincipals":
		return "id,appId,displayName,tags"
	case "users":
		return "id,displayName,department,mailNickname,userPrincipalName"
	case "groups":
		return "id,displayName,description,mailNickname,securityEnabled,mailEnabled,isAssignableToRole"
	}
	return "id"
}

func entraNext(collection, next string) bool {
	u, err := url.Parse(next)
	if err != nil || len(next) > 8192 || u.User != nil || u.Fragment != "" || u.RawQuery == "" {
		return false
	}
	u.RawQuery = ""
	return u.String() == collection
}

func (g entraGraph) listOwned(ctx context.Context, prefix, collection string) ([]entraObject, error) {
	var filters []string
	for _, name := range entraNames(prefix, collection) {
		filters = append(filters, "displayName eq '"+name+"'")
	}
	if !validEntraPrefix(prefix) || len(filters) == 0 {
		return nil, errors.New("entra: refused invalid ownership selector")
	}
	base := entraGraphBase + collection
	next := base + "?" + url.Values{"$filter": {strings.Join(filters, " or ")}, "$select": {entraSelect(collection)}, "$top": {"100"}}.Encode()
	var objects []entraObject
	seen := make(map[string]bool)
	for range 20 {
		if seen[next] {
			return nil, errors.New("entra: ownership paging cycle")
		}
		seen[next] = true
		var page struct {
			Value *[]entraObject `json:"value"`
			Next  string         `json:"@odata.nextLink"`
		}
		if err := g.rest(ctx, "discover owned "+collection, entraReadPermission, "GET", next, nil, &page); err != nil {
			return nil, err
		}
		if page.Value == nil || len(*page.Value) > 100 {
			return nil, errors.New("entra: invalid ownership page")
		}
		for _, object := range *page.Value {
			if !entraOwns(prefix, collection, object) {
				return nil, errors.New("entra: exact-name collision lacks fixture ownership; refusing deletion")
			}
			objects = append(objects, object)
		}
		if page.Next == "" {
			return objects, nil
		}
		if !entraNext(base, page.Next) {
			return nil, errors.New("entra: refused foreign ownership page")
		}
		next = page.Next
	}
	return nil, errors.New("entra: ownership paging limit exceeded")
}

func provisionEntra(ctx context.Context, runDir, prefix string) (_ *entraTenant, err error) {
	if !validEntraPrefix(prefix) {
		return nil, errors.New("entra: provisioning requires a full lindm-entra-check UUIDv4 prefix")
	}
	info, err := os.Lstat(runDir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("entra: provisioning requires a private run directory")
	}
	graph, tenant, err := entraAccount(ctx, runDir)
	if err != nil {
		return nil, err
	}
	for _, collection := range []string{"applications", "servicePrincipals", "users", "groups"} {
		objects, err := graph.listOwned(ctx, prefix, collection)
		if err != nil {
			return nil, err
		}
		if len(objects) != 0 {
			return nil, errors.New("entra: prefix already exists; refusing to adopt an earlier run")
		}
	}
	journal, err := os.OpenFile(filepath.Join(runDir, "entra-owned.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, errors.New("entra: cannot create exclusive ownership journal")
	}
	defer func() { err = errors.Join(err, journal.Close()) }()
	var owned []entraOwned
	defer func() {
		if err != nil {
			err = errors.Join(err, graph.cleanup(context.WithoutCancel(ctx), prefix, owned))
		}
	}()
	create := func(collection string, payload any, permission string) (entraObject, error) {
		var object entraObject
		requestErr := graph.rest(ctx, "create "+collection, permission, "POST", entraGraphBase+collection, payload, &object)
		if !entraUUID(object.ID) {
			if requestErr != nil {
				return object, requestErr
			}
			return object, errors.New("entra: creation returned an invalid object ID")
		}
		record := entraOwned{collection, object.ID}
		owned = append(owned, record)
		if err := json.NewEncoder(journal).Encode(record); err != nil {
			return object, errors.Join(requestErr, errors.New("entra: cannot record created ownership"))
		}
		if err := journal.Sync(); err != nil {
			return object, errors.Join(requestErr, errors.New("entra: cannot persist created ownership"))
		}
		return object, requestErr
	}
	var organization struct {
		Value []struct {
			ID      string `json:"id"`
			Domains []struct {
				Name    string `json:"name"`
				Initial bool   `json:"isInitial"`
				Type    string `json:"type"`
			} `json:"verifiedDomains"`
		} `json:"value"`
	}
	if err := graph.rest(ctx, "read verified initial domain", "Organization.Read.All delegated permission and a directory-reading role", "GET", entraGraphBase+"organization?$select=id,verifiedDomains", nil, &organization); err != nil {
		return nil, err
	}
	domain := ""
	if len(organization.Value) == 1 && organization.Value[0].ID == tenant {
		for _, candidate := range organization.Value[0].Domains {
			// organization.verifiedDomains already contains verifiedDomain
			// objects; unlike /domains, that Graph type has no isVerified field.
			if candidate.Initial && candidate.Type == "Managed" && strings.HasSuffix(candidate.Name, ".onmicrosoft.com") && !strings.ContainsAny(candidate.Name, "/@\\ \t\r\n") {
				domain = candidate.Name
			}
		}
	}
	if domain == "" {
		return nil, errors.New("entra: tenant has no verified public-cloud initial domain")
	}
	var resource struct {
		Value []struct {
			ID    string `json:"id"`
			Roles []struct {
				ID      string   `json:"id"`
				Value   string   `json:"value"`
				Enabled bool     `json:"isEnabled"`
				Members []string `json:"allowedMemberTypes"`
			} `json:"appRoles"`
			Scopes []struct {
				ID      string `json:"id"`
				Value   string `json:"value"`
				Enabled bool   `json:"isEnabled"`
			} `json:"oauth2PermissionScopes"`
		} `json:"value"`
	}
	if err := graph.rest(ctx, "read Microsoft Graph permissions", entraReadPermission, "GET", entraGraphBase+"servicePrincipals?"+url.Values{"$filter": {"appId eq '" + entraGraphApp + "'"}, "$select": {"id,appRoles,oauth2PermissionScopes"}}.Encode(), nil, &resource); err != nil {
		return nil, err
	}
	if len(resource.Value) != 1 || !entraUUID(resource.Value[0].ID) {
		return nil, errors.New("entra: Microsoft Graph service principal is missing or ambiguous")
	}
	graphSP := resource.Value[0]
	readRole := ""
	for _, role := range graphSP.Roles {
		for _, member := range role.Members {
			if role.Value == "User.Read.All" && role.Enabled && member == "Application" && entraUUID(role.ID) {
				readRole = role.ID
			}
		}
	}
	var scopes []map[string]string
	for _, name := range []string{"openid", "profile"} {
		for _, scope := range graphSP.Scopes {
			if scope.Value == name && scope.Enabled && entraUUID(scope.ID) {
				scopes = append(scopes, map[string]string{"id": scope.ID, "type": "Scope"})
			}
		}
	}
	if readRole == "" || len(scopes) != 2 {
		return nil, errors.New("entra: required Microsoft Graph permissions are unavailable")
	}
	t := &entraTenant{tenant: tenant, prefix: prefix, graph: graph}
	for _, kind := range []string{"login", "directory"} {
		access := scopes
		if kind == "directory" {
			access = []map[string]string{{"id": readRole, "type": "Role"}}
		}
		payload := map[string]any{"displayName": prefix + "-" + kind, "description": prefix, "signInAudience": "AzureADMyOrg", "requiredResourceAccess": []any{map[string]any{"resourceAppId": entraGraphApp, "resourceAccess": access}}}
		if kind == "login" {
			payload["web"] = map[string]any{"redirectUris": []string{}, "implicitGrantSettings": map[string]bool{"enableAccessTokenIssuance": false, "enableIdTokenIssuance": false}}
			payload["isFallbackPublicClient"] = false
		}
		app, err := create("applications", payload, entraAppPermission)
		if err != nil {
			return nil, err
		}
		if !entraUUID(app.AppID) {
			return nil, errors.New("entra: application returned an invalid client ID")
		}
		sp, err := create("servicePrincipals", map[string]any{"appId": app.AppID, "displayName": prefix + "-" + kind, "tags": []string{prefix}}, entraAppPermission)
		if err != nil {
			return nil, err
		}
		var password struct {
			Secret string `json:"secretText"`
		}
		if err := graph.rest(ctx, "create "+kind+" client secret", entraAppPermission, "POST", entraGraphBase+"applications/"+app.ID+"/addPassword", map[string]any{"passwordCredential": map[string]string{"displayName": prefix, "endDateTime": time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)}}, &password); err != nil {
			return nil, err
		}
		if password.Secret == "" {
			return nil, errors.New("entra: returned an empty client secret")
		}
		if kind == "login" {
			t.loginObject, t.loginID, t.loginSecret = app.ID, app.AppID, password.Secret
			if err := graph.rest(ctx, "consent login openid/profile", "DelegatedPermissionGrant.ReadWrite.All delegated permission and Cloud Application Administrator (or a role permitted to grant tenant-wide consent)", "POST", entraGraphBase+"oauth2PermissionGrants", map[string]string{"clientId": sp.ID, "consentType": "AllPrincipals", "resourceId": graphSP.ID, "scope": "openid profile"}, nil); err != nil {
				return nil, err
			}
		} else {
			t.directoryID, t.directorySecret = app.AppID, password.Secret
			if err := graph.rest(ctx, "grant directory User.Read.All application consent", "AppRoleAssignment.ReadWrite.All and Application.Read.All delegated permissions plus Privileged Role Administrator for Microsoft Graph application permissions (Global Administrator also qualifies)", "POST", entraGraphBase+"servicePrincipals/"+sp.ID+"/appRoleAssignments", map[string]string{"principalId": sp.ID, "resourceId": graphSP.ID, "appRoleId": readRole}, nil); err != nil {
				return nil, err
			}
		}
	}
	for _, kind := range []string{"owner", "admin"} {
		var entropy [32]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			return nil, errors.New("entra: cannot generate user password")
		}
		password := "Aa1!" + base64.RawURLEncoding.EncodeToString(entropy[:])
		clear(entropy[:])
		name := prefix + "-" + kind
		user, err := create("users", map[string]any{"accountEnabled": true, "displayName": name, "mailNickname": name, "department": prefix, "userPrincipalName": name + "@" + domain, "passwordProfile": map[string]any{"password": password, "forceChangePasswordNextSignIn": false}}, entraUserPermission)
		if err != nil {
			return nil, err
		}
		if kind == "owner" {
			t.ownerID, t.ownerUPN, t.ownerPassword = user.ID, name+"@"+domain, password
		} else {
			t.adminID, t.adminUPN, t.adminPassword = user.ID, name+"@"+domain, password
		}
	}
	group, err := create("groups", map[string]any{"displayName": prefix + "-admins", "description": prefix, "mailNickname": prefix + "-admins", "mailEnabled": false, "securityEnabled": true, "groupTypes": []string{}, "isAssignableToRole": false}, entraGroupPermission)
	if err != nil {
		return nil, err
	}
	t.group = group.ID
	if err := t.membership(ctx, true); err != nil {
		return nil, err
	}
	readyCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	for {
		ready, observeErr := t.observe(readyCtx, false)
		if observeErr == nil && ready {
			owner := *t
			owner.adminID = t.ownerID
			var disabled bool
			disabled, observeErr = owner.observe(readyCtx, true)
			if observeErr == nil && !disabled {
				t.owned = owned
				return t, nil
			}
		}
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-readyCtx.Done():
			timer.Stop()
			return nil, errors.Join(errors.New("entra: directory application permission or initial membership did not become visible before deadline"), observeErr, readyCtx.Err())
		case <-timer.C:
		}
	}
}

func (g entraGraph) requireOwned(ctx context.Context, prefix, collection, id string) error {
	if !validEntraPrefix(prefix) || !entraUUID(id) {
		return errors.New("entra: refused invalid mutation ownership")
	}
	var object entraObject
	if err := g.rest(ctx, "verify owned "+collection, entraReadPermission, "GET", entraGraphBase+collection+"/"+id+"?$select="+entraSelect(collection), nil, &object); err != nil {
		return err
	}
	if object.ID != id || !entraOwns(prefix, collection, object) {
		return errors.New("entra: refused mutation of an object without exact fixture ownership")
	}
	return nil
}

func (t *entraTenant) redirect(ctx context.Context, origin string) error {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path != "" || u.RawPath != "" || u.Port() == "" {
		return errors.New("entra: redirect requires an exact HTTPS loopback origin with explicit port")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return errors.New("entra: redirect requires a valid loopback port")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return errors.New("entra: redirect requires a loopback host")
	}
	if err := t.graph.requireOwned(ctx, t.prefix, "applications", t.loginObject); err != nil {
		return err
	}
	return t.graph.rest(ctx, "register exact login callback", entraAppPermission, "PATCH", entraGraphBase+"applications/"+t.loginObject, map[string]any{"web": map[string]any{"redirectUris": []string{origin + "/auth/callback"}}}, nil)
}

func (t *entraTenant) membership(ctx context.Context, present bool) error {
	if err := t.graph.requireOwned(ctx, t.prefix, "groups", t.group); err != nil {
		return err
	}
	if err := t.graph.requireOwned(ctx, t.prefix, "users", t.adminID); err != nil {
		return err
	}
	if present {
		return t.graph.rest(ctx, "add test admin membership", entraGroupPermission, "POST", entraGraphBase+"groups/"+t.group+"/members/$ref", map[string]string{"@odata.id": entraGraphBase + "directoryObjects/" + t.adminID}, nil)
	}
	return t.graph.rest(ctx, "remove test admin membership", entraGroupPermission, "DELETE", entraGraphBase+"groups/"+t.group+"/members/"+t.adminID+"/$ref", nil, nil)
}

func (t *entraTenant) enabled(ctx context.Context, enabled bool) error {
	if err := t.graph.requireOwned(ctx, t.prefix, "users", t.adminID); err != nil {
		return err
	}
	return t.graph.rest(ctx, "set test admin accountEnabled", "User.EnableDisableAccount.All and User.Read.All delegated permissions (or User.ReadWrite.All), plus User Administrator for this non-admin test user", "PATCH", entraGraphBase+"users/"+t.adminID, map[string]bool{"accountEnabled": enabled}, nil)
}

// Observation uses the directory application's real credential, not the operator's
// elevated CLI token. The eventual transitive query matches the production source.
func (t *entraTenant) observe(ctx context.Context, disabled bool) (bool, error) {
	if !entraUUID(t.tenant) || !entraUUID(t.directoryID) || !entraUUID(t.adminID) || !entraUUID(t.group) {
		return false, errors.New("entra: observation has invalid object IDs")
	}
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {t.directoryID}, "client_secret": {t.directorySecret}, "scope": {"https://graph.microsoft.com/.default"}}
	request, err := http.NewRequestWithContext(ctx, "POST", "https://login.microsoftonline.com/"+t.tenant+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	if err != nil {
		return false, errors.New("entra: cannot construct directory token request")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Cache-Control", "no-cache")
	body, err := entraHTTP(client, request, "acquire directory app token")
	if err != nil {
		return false, err
	}
	var token struct {
		Access string `json:"access_token"`
		Type   string `json:"token_type"`
	}
	decodeErr := json.Unmarshal(body, &token)
	clear(body)
	if decodeErr != nil || token.Access == "" || !strings.EqualFold(token.Type, "Bearer") {
		return false, errors.New("entra: directory app returned an invalid token response")
	}
	base := entraGraphBase + "users/" + t.adminID
	next := base + "?$select=id,accountEnabled"
	if !disabled {
		base += "/transitiveMemberOf/microsoft.graph.group"
		next = base + "?$select=id&$count=true&$top=100"
	}
	seen := make(map[string]bool)
	found := false
	for range 20 {
		if seen[next] {
			return false, errors.New("entra: observation paging cycle")
		}
		seen[next] = true
		request, err := http.NewRequestWithContext(ctx, "GET", next, nil)
		if err != nil {
			return false, errors.New("entra: cannot construct directory observation")
		}
		request.Header.Set("Authorization", "Bearer "+token.Access)
		request.Header.Set("ConsistencyLevel", "eventual")
		request.Header.Set("Cache-Control", "no-cache")
		body, err := entraHTTP(client, request, "observe directory app user or membership")
		if err != nil {
			return false, err
		}
		if disabled {
			var user struct {
				ID      string `json:"id"`
				Enabled *bool  `json:"accountEnabled"`
			}
			if json.Unmarshal(body, &user) != nil || user.ID != t.adminID || user.Enabled == nil {
				return false, errors.New("entra: malformed enabled observation")
			}
			return !*user.Enabled, nil
		}
		var page struct {
			Value *[]struct {
				ID string `json:"id"`
			} `json:"value"`
			Next string `json:"@odata.nextLink"`
		}
		if json.Unmarshal(body, &page) != nil || page.Value == nil || len(*page.Value) > 100 {
			return false, errors.New("entra: malformed membership observation")
		}
		for _, group := range *page.Value {
			if !entraUUID(group.ID) {
				return false, errors.New("entra: malformed membership ID")
			}
			found = found || group.ID == t.group
		}
		if page.Next == "" {
			return found, nil
		}
		if !entraNext(base, page.Next) {
			return false, errors.New("entra: refused foreign membership page")
		}
		next = page.Next
	}
	return false, errors.New("entra: membership paging limit exceeded")
}

func entraHTTP(client *http.Client, request *http.Request, operation string) ([]byte, error) {
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("entra: %s: transport failure (details withheld)", operation)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, entraOutputLimit+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(body) > entraOutputLimit {
		return nil, fmt.Errorf("entra: %s: invalid or oversized response", operation)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, &entraGraphError{fmt.Sprintf("%s (HTTP %d)", operation, response.StatusCode), entraErrorCode(body), "a valid directory client secret and admin-consented Microsoft Graph User.Read.All application permission; consent replication may be pending"}
	}
	return body, nil
}

// Retain the original Azure subscription and known IDs even if the operator
// changes the CLI default account or Graph discovery has not converged.
func (t *entraTenant) cleanup(ctx context.Context) error {
	return t.graph.cleanup(ctx, t.prefix, t.owned)
}

func cleanupEntra(ctx context.Context, prefix string) error {
	if !validEntraPrefix(prefix) {
		return errors.New("entra: cleanup requires a full lindm-entra-check UUIDv4 prefix")
	}
	ctx = context.WithoutCancel(ctx)
	graph, _, err := entraAccount(ctx, "")
	if err != nil {
		return err
	}
	return graph.cleanup(ctx, prefix, nil)
}

func (g entraGraph) cleanup(ctx context.Context, prefix string, known []entraOwned) error {
	ctx = context.WithoutCancel(ctx)
	var failures []error
	deleted := make(map[entraOwned]bool)
	remove := func(record entraOwned) {
		if deleted[record] {
			return
		}
		if err := g.requireOwned(ctx, prefix, record.Collection, record.ID); err != nil {
			if !entraMissing(err) {
				failures = append(failures, err)
			}
			return
		}
		permission := entraAppPermission
		switch record.Collection {
		case "users":
			permission = entraUserPermission
		case "groups":
			permission = entraGroupPermission
		}
		err := g.rest(ctx, "delete owned "+record.Collection, permission, "DELETE", entraGraphBase+record.Collection+"/"+record.ID, nil, nil)
		if err != nil && !entraMissing(err) {
			failures = append(failures, err)
			return
		}
		deleted[record] = true
	}
	// Known IDs avoid discovery-index lag after partially successful creation.
	// Service principals are removed before applications (which can cascade).
	for _, collection := range []string{"groups", "users", "servicePrincipals", "applications"} {
		for _, record := range known {
			if record.Collection == collection {
				remove(record)
			}
		}
		objects, err := g.listOwned(ctx, prefix, collection)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		for _, object := range objects {
			remove(entraOwned{collection, object.ID})
		}
	}
	return errors.Join(failures...)
}
