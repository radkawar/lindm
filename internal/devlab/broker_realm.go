// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"time"
)

const (
	brokerRealm          = "lindm-broker"
	brokerUpstreamRealm  = "lindm-upstream"
	brokerAlias          = "owned-saml-upstream"
	brokerIssuer         = "https://localhost:18443/realms/" + brokerRealm
	brokerUpstreamIssuer = "https://localhost:18443/realms/" + brokerUpstreamRealm
	brokerSAMLClient     = brokerIssuer
	brokerOwnedPrefix    = "lindm-broker-check-"
)

// brokerRealmFiles runs only during explicit fixture initialization. No runtime
// check updates shared realms or needs a master-realm credential. Only the broker
// realm's lab-admin can manage clients, for exact ephemeral redirect registration.
func brokerRealmFiles(secrets map[string]string) (map[string][]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	certificate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "lindm owned SAML upstream"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(5, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	defer clear(private)
	cert := base64.StdEncoding.EncodeToString(der)
	upstream := brokerBaseRealm(brokerUpstreamRealm, secrets["broker-upstream-directory-secret"], secrets["broker-upstream-admin-secret"], false)
	upstream["components"] = map[string]any{
		"org.keycloak.keys.KeyProvider": []any{map[string]any{"name": "owned-saml-signing", "providerId": "rsa", "config": map[string][]string{
			"priority": {"100"}, "enabled": {"true"}, "active": {"true"}, "algorithm": {"RS256"},
			"privateKey": {base64.StdEncoding.EncodeToString(private)}, "certificate": {cert},
		}}},
		"org.keycloak.userprofile.UserProfileProvider": []any{map[string]any{"providerId": "declarative-user-profile", "config": map[string][]string{
			"kc.user.profile.config": {`{"unmanagedAttributePolicy":"ADMIN_EDIT","attributes":[{"name":"username","permissions":{"view":["admin","user"],"edit":["admin"]}},{"name":"email","permissions":{"view":["admin","user"],"edit":["admin"]}},{"name":"firstName","permissions":{"view":["admin","user"],"edit":["admin"]}},{"name":"lastName","permissions":{"view":["admin","user"],"edit":["admin"]}}]}`},
		}}},
	}
	upstreamClients, ok := upstream["clients"].([]any)
	if !ok {
		return nil, errors.New("broker fixture upstream clients have invalid representation")
	}
	upstream["clients"] = append(upstreamClients, map[string]any{
		"clientId": brokerSAMLClient, "enabled": true, "protocol": "saml", "frontchannelLogout": true,
		"redirectUris": []string{brokerIssuer + "/broker/" + brokerAlias + "/endpoint"},
		"attributes": map[string]string{
			"saml.assertion.signature": "true", "saml.server.signature": "true", "saml.signature.algorithm": "RSA_SHA256",
			"saml.client.signature": "false", "saml.force.post.binding": "true", "saml_name_id_format": "persistent", "saml_force_name_id_format": "true",
		},
	})
	broker := brokerBaseRealm(brokerRealm, secrets["broker-directory-secret"], secrets["broker-admin-secret"], true)
	broker["identityProviders"] = []any{map[string]any{
		"alias": brokerAlias, "providerId": "saml", "enabled": true, "trustEmail": false, "storeToken": false,
		"config": map[string]string{
			"singleSignOnServiceUrl": brokerUpstreamIssuer + "/protocol/saml", "idpEntityId": brokerUpstreamIssuer,
			"entityId": brokerIssuer, "nameIDPolicyFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
			"validateSignature": "true", "signingCertificate": cert, "wantAssertionsSigned": "true",
			"postBindingResponse": "true", "postBindingAuthnRequest": "true", "wantAuthnRequestsSigned": "false", "syncMode": "IMPORT",
		},
	}}
	// Copy the verified persistent NameID to a broker SESSION note, never an
	// editable profile attribute. The OIDC client maps that note to a signed claim.
	broker["identityProviderMappers"] = []any{map[string]any{
		"name": "persistent-nameid-session-proof", "identityProviderAlias": brokerAlias, "identityProviderMapper": "saml-username-idp-mapper",
		"config": map[string]string{"template": "${NAMEID}", "target": "BROKER_USERNAME", "syncMode": "INHERIT"},
	}}
	out := make(map[string][]byte, 2)
	for name, realm := range map[string]map[string]any{"broker-upstream-realm.json": upstream, "broker-realm.json": broker} {
		out[name], err = json.MarshalIndent(realm, "", "  ")
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func brokerBaseRealm(name, directorySecret, adminSecret string, clients bool) map[string]any {
	service := func(id, secret string) map[string]any {
		return map[string]any{"clientId": id, "enabled": true, "protocol": "openid-connect", "publicClient": false,
			"secret": secret, "clientAuthenticatorType": "client-secret", "standardFlowEnabled": false,
			"directAccessGrantsEnabled": false, "serviceAccountsEnabled": true, "fullScopeAllowed": true, "defaultClientScopes": []string{"roles"}}
	}
	user := func(id string, roles []string) map[string]any {
		return map[string]any{"username": "service-account-" + id, "enabled": true, "serviceAccountClientId": id, "clientRoles": map[string]any{"realm-management": roles}}
	}
	adminRoles := []string{"manage-users", "view-users", "query-users"}
	if clients {
		adminRoles = append(adminRoles, "manage-clients")
	}
	return map[string]any{"realm": name, "enabled": true, "sslRequired": "all", "registrationAllowed": false,
		"resetPasswordAllowed": false, "loginWithEmailAllowed": false, "duplicateEmailsAllowed": false,
		"clients": []any{service("lindm-directory", directorySecret), service("lindm-lab-admin", adminSecret)},
		"users":   []any{user("lindm-directory", []string{"view-users", "query-users"}), user("lindm-lab-admin", adminRoles)}}
}

func brokerClient(name, secret, origin string) map[string]any {
	noteMapper := func(note, claim string) map[string]any {
		return map[string]any{"name": claim, "protocol": "openid-connect", "protocolMapper": "oidc-usersessionmodel-note-mapper",
			"config": map[string]string{"user.session.note": note, "claim.name": claim, "jsonType.label": "String", "id.token.claim": "true", "access.token.claim": "false"}}
	}
	return map[string]any{"clientId": name, "enabled": true, "protocol": "openid-connect", "publicClient": false,
		"secret": secret, "clientAuthenticatorType": "client-secret", "standardFlowEnabled": true, "implicitFlowEnabled": false,
		"directAccessGrantsEnabled": false, "serviceAccountsEnabled": false, "redirectUris": []string{origin + "/auth/callback"},
		"webOrigins": []string{origin}, "attributes": map[string]string{"pkce.code.challenge.method": "S256"},
		"protocolMappers": []any{noteMapper("identity_provider", "lindm_upstream_alias"), noteMapper("identity_provider_identity", "lindm_upstream_subject")}}
}
