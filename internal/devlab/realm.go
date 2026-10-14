// SPDX-License-Identifier: Apache-2.0

package devlab

import "encoding/json"

const issuer = "https://localhost:18443/realms/lindm"
const ownerSubject = "00000000-0000-4000-8000-000000000001"

func realmFile(secrets map[string]string) ([]byte, error) {
	// Realm import representations belong to Keycloak, not the server config.
	serviceClient := func(id, secret string) map[string]any {
		return map[string]any{
			"clientId": id, "enabled": true, "protocol": "openid-connect",
			"publicClient": false, "secret": secret, "clientAuthenticatorType": "client-secret",
			"standardFlowEnabled": false, "implicitFlowEnabled": false,
			"directAccessGrantsEnabled": false, "serviceAccountsEnabled": true,
			"fullScopeAllowed": true, "defaultClientScopes": []string{"roles"},
		}
	}
	serviceUser := func(id string, roles []string) map[string]any {
		return map[string]any{
			"username": "service-account-" + id, "enabled": true,
			"serviceAccountClientId": id,
			"clientRoles":            map[string]any{"realm-management": roles},
		}
	}
	human := func(id, username, password string) map[string]any {
		return map[string]any{
			"id": id, "username": username, "enabled": true,
			"email": username + "@lindm.example", "emailVerified": true,
			"firstName": username, "lastName": "Development",
			"requiredActions": []string{}, "groups": []string{"/mdm-admins"},
			"credentials": []any{map[string]any{"type": "password", "value": password, "temporary": false}},
		}
	}
	return json.MarshalIndent(map[string]any{
		"realm": "lindm", "enabled": true, "sslRequired": "all",
		"registrationAllowed": false, "resetPasswordAllowed": false,
		"loginWithEmailAllowed": false, "duplicateEmailsAllowed": false,
		"groups": []any{map[string]any{"id": "00000000-0000-4000-8000-000000000100", "name": "mdm-admins"}},
		"clients": []any{
			map[string]any{
				"clientId": "lindm-console", "enabled": true, "protocol": "openid-connect",
				"publicClient": false, "secret": secrets["console-secret"], "clientAuthenticatorType": "client-secret",
				"standardFlowEnabled": true, "implicitFlowEnabled": false,
				"directAccessGrantsEnabled": false, "serviceAccountsEnabled": false,
				"redirectUris":        []string{"https://localhost:18444/auth/callback"},
				"webOrigins":          []string{"https://localhost:18444"},
				"attributes":          map[string]string{"pkce.code.challenge.method": "S256"},
				"defaultClientScopes": []string{"profile", "email"},
			},
			serviceClient("lindm-directory", secrets["directory-secret"]),
			serviceClient("lindm-lab-admin", secrets["lab-admin-secret"]),
		},
		"users": []any{
			human(ownerSubject, "owner", secrets["owner-password"]),
			human("00000000-0000-4000-8000-000000000002", "administrator", secrets["administrator-password"]),
			serviceUser("lindm-directory", []string{"view-users", "query-users"}),
			serviceUser("lindm-lab-admin", []string{"manage-users", "view-users", "query-users"}),
		},
	}, "", "  ")
}
