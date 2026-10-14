// SPDX-License-Identifier: Apache-2.0

package device

import (
	"context"
	"reflect"
	"slices"
	"testing"

	"lindm/internal/device/assistance"
	"lindm/internal/device/core"
	"lindm/internal/device/directory"
	"lindm/internal/device/dispatch"
	"lindm/internal/device/inventory"
	"lindm/internal/device/secrets"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/identity"
)

type adminAuthorizationCase struct {
	permission identity.Permission
	roles      []string
	global     bool
}

// Every generated RPC must declare its authorization boundary here. Empty
// permissions are the approval inbox/create operations whose authority depends
// on the stored/requested action; their lifecycle is exercised separately.
func adminAuthorizationCases() map[string]adminAuthorizationCase {
	readers := []string{"owner", "admin", "operator", "helpdesk", "auditor"}
	admins := []string{"owner", "admin"}
	operators := []string{"owner", "admin", "operator"}
	accounts := []string{"owner"}
	return map[string]adminAuthorizationCase{
		"GetAuthorization":                     {identity.PermissionManageAccounts, accounts, true},
		"UpdateAuthorization":                  {identity.PermissionManageAccounts, accounts, true},
		"GetServerStatus":                      {identity.PermissionManageIntegrations, admins, true},
		"ConfirmRecoveryKeyCustody":            {identity.PermissionManageExecutionTrust, accounts, true},
		"CreateProvisioningToken":              {identity.PermissionManageEnrollment, []string{"owner", "admin", "operator", "helpdesk"}, true},
		"ListProvisioningTokens":               {identity.PermissionManageEnrollment, []string{"owner", "admin", "operator", "helpdesk"}, true},
		"RevokeProvisioningToken":              {identity.PermissionManageEnrollment, []string{"owner", "admin", "operator", "helpdesk"}, true},
		"GetPendingEnrollments":                {identity.PermissionManageEnrollment, []string{"owner", "admin", "operator", "helpdesk"}, true},
		"ApprovePendingEnrollment":             {identity.PermissionManageEnrollment, []string{"owner", "admin", "operator", "helpdesk"}, true},
		"CreateRecoveryEnrollmentGrant":        {identity.PermissionRevokeDevice, admins, false},
		"CreateOfflineEnrollmentAuthorization": {identity.PermissionManageEnrollment, []string{"owner", "admin", "operator", "helpdesk"}, true},
		"ImportOfflineEnrollmentRequest":       {identity.PermissionManageEnrollment, []string{"owner", "admin", "operator", "helpdesk"}, true},
		"ExportOfflineEnrollmentResponse":      {identity.PermissionManageEnrollment, []string{"owner", "admin", "operator", "helpdesk"}, true},
		"ListDevices":                          {identity.PermissionReadFleet, readers, false},
		"GetFleetSummary":                      {identity.PermissionReadFleet, readers, false},
		"GetDevice":                            {identity.PermissionReadFleet, readers, false},
		"ListDevicePackages":                   {identity.PermissionReadFleet, readers, false},
		"SetDeviceMetadata":                    {identity.PermissionManageInventory, admins, false},
		"SetAttributeDefinition":               {identity.PermissionManageInventory, admins, true},
		"ListAttributeDefinitions":             {identity.PermissionReadFleet, readers, true},
		"ExportDevices":                        {identity.PermissionReadFleet, readers, false},
		"CreateEnrollmentGrant":                {identity.PermissionManageEnrollment, []string{"owner", "admin", "operator", "helpdesk"}, true},
		"ListEnrollmentGrants":                 {identity.PermissionManageEnrollment, []string{"owner", "admin", "operator", "helpdesk"}, true},
		"GetEnrollmentInstructions":            {identity.PermissionManageEnrollment, []string{"owner", "admin", "operator", "helpdesk"}, true},
		"RevokeEnrollmentGrant":                {identity.PermissionManageEnrollment, []string{"owner", "admin", "operator", "helpdesk"}, true},
		"RevokeDevice":                         {identity.PermissionRevokeDevice, admins, false},
		"CreateApproval":                       {},
		"WithdrawApproval":                     {},
		"ListApprovals":                        {},
		"ApproveApproval":                      {identity.PermissionManageApprovals, admins, false},
		"RejectApproval":                       {identity.PermissionManageApprovals, admins, false},
		"ListAuditEvents":                      {identity.PermissionReadAudit, []string{"owner", "admin", "auditor"}, true},
		"ListAuditActors":                      {identity.PermissionReadAudit, []string{"owner", "admin", "auditor"}, true},
		"ListAuditDevices":                     {identity.PermissionReadAudit, []string{"owner", "admin", "auditor"}, true},
		"GetExecutionAuthority":                {identity.PermissionReadFleet, readers, true},
		"UpdateExecutionAuthority":             {identity.PermissionManageExecutionTrust, admins, true},
		"ListCapabilityPolicies":               {identity.PermissionReadFleet, readers, true},
		"SetCapabilityPolicy":                  {identity.PermissionManageExecutionTrust, admins, true},
		"PublishProfileRevision":               {identity.PermissionManageProfiles, operators, true},
		"GetProfileRevision":                   {identity.PermissionReadFleet, readers, true},
		"ListProfiles":                         {identity.PermissionReadFleet, readers, true},
		"ListProfileRevisions":                 {identity.PermissionReadFleet, readers, true},
		"ListQualifiedResourceKinds":           {identity.PermissionReadFleet, readers, true},
		"SetResourceAssignment":                {identity.PermissionAssignResources, operators, false},
		"GetDeviceResourceState":               {identity.PermissionReadFleet, readers, false},
		"PutDynamicGroup":                      {identity.PermissionManageInventory, admins, false},
		"ListDynamicGroups":                    {identity.PermissionManageInventory, admins, false},
		"GetDynamicGroup":                      {identity.PermissionManageInventory, admins, false},
		"PreviewDynamicGroup":                  {identity.PermissionManageInventory, admins, false},
		"PutTargetAssignment":                  {identity.PermissionAssignResources, operators, false},
		"ListTargetAssignments":                {identity.PermissionAssignResources, operators, false},
		"PreviewTargetAssignments":             {identity.PermissionAssignResources, operators, false},
		"PreviewTargetAssignmentImpact":        {identity.PermissionAssignResources, operators, false},
		"StartRollout":                         {identity.PermissionAssignResources, operators, false},
		"ListRolloutDevices":                   {identity.PermissionAssignResources, operators, false},
		"ActivateTargetPreview":                {identity.PermissionAssignResources, operators, false},
		"PutRollout":                           {identity.PermissionAssignResources, operators, false},
		"ControlRollout":                       {identity.PermissionAssignResources, operators, false},
		"ListRollouts":                         {identity.PermissionAssignResources, operators, false},
		"CreateDeviceAction":                   {identity.PermissionRunRemoteExecution, admins, false},
		"PreflightDeviceAction":                {identity.PermissionRunRemoteExecution, admins, false},
		"GetDeviceActions":                     {identity.PermissionReadFleet, readers, false},
		"GetDeviceAction":                      {identity.PermissionReadFleet, readers, false},
		"GetDeviceEncryption":                  {identity.PermissionReadFleet, readers, false},
		"ListDeviceStorageTargets":             {identity.PermissionReadFleet, readers, false},
		"RevealRecoveryKey":                    {identity.PermissionReadRecoveryKeys, admins, false},
		"ListDeviceGroups":                     {identity.PermissionManageAccounts, accounts, true},
		"SetDeviceGroup":                       {identity.PermissionManageAccounts, accounts, true},
		"DeleteDeviceGroup":                    {identity.PermissionManageAccounts, accounts, true},
		"ListDeviceFindings":                   {identity.PermissionReadFleet, readers, false},
		"ListDeviceUncoveredPackages":          {identity.PermissionReadFleet, readers, false},
		"ListAdvisorySummary":                  {identity.PermissionReadFleet, readers, false},
		"ListAdvisoryFeeds":                    {identity.PermissionReadFleet, readers, true},
		"AcceptAdvisoryFinding":                {identity.PermissionManageAdvisoryExceptions, admins, false},
		// Per field: device fields read fleet.read within scope (the zero request
		// is checked as one); DIRECTORY_GROUP requires unrestricted accounts.manage.
		"SuggestValues": {identity.PermissionReadFleet, readers, false},
		// Device-reported approvals within the caller's fleet.read device scope.
		"ListApprovedReferences": {identity.PermissionReadFleet, readers, false},
		// Secrets are deployment-global: mutations require an unrestricted grant at
		// entry; reveal re-checks unrestricted authority inside its fenced transaction.
		"CreateSecret": {identity.PermissionManageSecrets, admins, true},
		"RotateSecret": {identity.PermissionManageSecrets, admins, true},
		"ListSecrets":  {identity.PermissionManageSecrets, admins, false},
		"GetSecret":    {identity.PermissionManageSecrets, admins, false},
		"RevealSecret": {identity.PermissionRevealSecrets, admins, false},
		// Uses name only devices within the caller's scope; deletion is global.
		"ListSecretUses": {identity.PermissionManageSecrets, admins, false},
		"DeleteSecret":   {identity.PermissionManageSecrets, admins, true},
		// Local-admin passwords are device-scoped; status is fleet-visible metadata.
		"SetLocalAdminPasswordPolicy":       {identity.PermissionManageSecrets, admins, false},
		"RemoveLocalAdminPasswordPolicy":    {identity.PermissionManageSecrets, admins, false},
		"RequestLocalAdminPasswordRotation": {identity.PermissionManageSecrets, admins, false},
		"GetLocalAdminPasswordStatus":       {identity.PermissionReadFleet, readers, false},
		"RevealLocalAdminPassword":          {identity.PermissionRevealSecrets, admins, false},
		// Join/Answer additionally require the creating operator; scoped grants
		// are exercised by the assistance integration tests.
		"CreateAssistanceSession":      {identity.PermissionViewRemoteAssistance, admins, false},
		"ListAssistanceSessions":       {identity.PermissionReadFleet, readers, false},
		"GetAssistanceSession":         {identity.PermissionReadFleet, readers, false},
		"JoinAssistanceSession":        {identity.PermissionViewRemoteAssistance, admins, false},
		"AnswerAssistanceSession":      {identity.PermissionViewRemoteAssistance, admins, false},
		"StopAssistanceSession":        {identity.PermissionViewRemoteAssistance, admins, false},
		"GetAssistanceReadiness":       {identity.PermissionViewRemoteAssistance, admins, false},
		"GetAssistancePolicy":          {identity.PermissionReadFleet, readers, false},
		"UpdateAssistancePolicy":       {identity.PermissionManageAssistancePolicy, admins, false},
		"RunAssistanceCommand":         {identity.PermissionViewRemoteAssistance, admins, false},
		"GetAssistanceCommand":         {identity.PermissionViewRemoteAssistance, admins, false},
		"StartAssistanceFileTransfer":  {identity.PermissionViewRemoteAssistance, admins, false},
		"GetAssistanceFileTransfer":    {identity.PermissionViewRemoteAssistance, admins, false},
		"CancelAssistanceFileTransfer": {identity.PermissionViewRemoteAssistance, admins, false},
		// Reconnect also requires the creator and remote_assistance.reconnect in
		// scope; archive retrieval/deletion never require or grant live access.
		"ReconnectAssistanceSession": {identity.PermissionViewRemoteAssistance, admins, false},
		"ListAssistanceRecordings":   {identity.PermissionReadFleet, readers, false},
		"OpenAssistanceRecording":    {identity.PermissionReadAssistanceRecordings, admins, false},
		"ReadAssistanceRecording":    {identity.PermissionReadAssistanceRecordings, admins, false},
		"DeleteAssistanceRecording":  {identity.PermissionDeleteAssistanceRecordings, admins, false},
		// Unattended grants consume an approval decided under the independent
		// approve permission; revocation accepts the requester, an approver or
		// a policy manager in scope.
		"AuthorizeUnattendedAssistance": {identity.PermissionAssistanceUnattended, admins, false},
		"ListUnattendedAssistance":      {identity.PermissionReadFleet, readers, false},
		"RevokeUnattendedAssistance":    {identity.PermissionAssistanceUnattended, admins, false},
	}
}

// Invoke the real generated handler signature, not a second authorization
// dispatcher. A zero service must be safe because denial precedes dependencies.
func invokeDeniedAdminRPC(t *testing.T, name string, ctx context.Context) error {
	t.Helper()
	method := reflect.ValueOf(composed(t, &core.Service{})).MethodByName(name)
	if !method.IsValid() {
		t.Fatalf("missing admin handler %s", name)
	}
	request := reflect.New(method.Type().In(1).Elem())
	message := request.Elem().FieldByName("Msg")
	message.Set(reflect.New(message.Type().Elem()))
	result := method.Call([]reflect.Value{reflect.ValueOf(ctx), request})
	if result[1].IsNil() {
		return nil
	}
	err, ok := result[1].Interface().(error)
	if !ok {
		t.Fatalf("admin handler %s returned a non-error result", name)
	}
	return err
}

// composed wires the domain services over c exactly as New does, without
// constructing dependencies; a zero core serves denial-first tests.
func composed(t *testing.T, c *core.Service) *Service {
	t.Helper()
	support, err := assistance.New(c, assistance.NewRuntime())
	if err != nil {
		t.Fatal(err)
	}
	facts, custody := inventory.New(c), secrets.New(c)
	return &Service{Service: c, assistanceService: support, directoryService: directory.New(c, facts), dispatchService: dispatch.New(c, custody, facts), inventoryService: facts, secretsService: custody}
}

func TestAdminRPCDenialMatrix(t *testing.T) {
	cases := adminAuthorizationCases()
	methods := adminv1.File_lindm_admin_v1_admin_proto.Services().ByName("AdminService").Methods()
	if methods.Len() != len(cases) {
		t.Fatalf("generated AdminService has %d methods, authorization matrix has %d", methods.Len(), len(cases))
	}
	for i := range methods.Len() {
		name := string(methods.Get(i).Name())
		policy, ok := cases[name]
		if !ok {
			t.Fatalf("RPC %s lacks an authorization test policy", name)
		}
		t.Run(name, func(t *testing.T) {
			if err := invokeDeniedAdminRPC(t, name, t.Context()); connect.CodeOf(err) != connect.CodeUnauthenticated {
				t.Fatalf("anonymous request: %v", err)
			}
			if policy.permission == "" {
				return
			}
			for _, role := range []string{"owner", "admin", "operator", "helpdesk", "auditor", "unknown"} {
				t.Run(role, func(t *testing.T) {
					principal := identity.Principal{ID: uuid.New(), Role: role}
					if !slices.Contains(policy.roles, role) {
						ctx := identity.WithPrincipal(t.Context(), principal)
						if err := invokeDeniedAdminRPC(t, name, ctx); connect.CodeOf(err) != connect.CodePermissionDenied {
							t.Fatalf("role denied: %v", err)
						}
					}
					// Explicit bindings replace the legacy display role. A grant
					// to an unknown permission must never inherit owner privileges.
					principal.Bindings = []*authv1.RoleBinding{{Permissions: []string{"unknown.permission"}}}
					if err := invokeDeniedAdminRPC(t, name, identity.WithPrincipal(t.Context(), principal)); connect.CodeOf(err) != connect.CodePermissionDenied {
						t.Fatalf("unknown binding admitted: %v", err)
					}
					if policy.global {
						principal.Bindings = []*authv1.RoleBinding{{Permissions: []string{string(policy.permission)}, Scopes: []*authv1.DeviceScope{{DeviceIds: []string{uuid.NewString()}}}}}
						if err := invokeDeniedAdminRPC(t, name, identity.WithPrincipal(t.Context(), principal)); connect.CodeOf(err) != connect.CodePermissionDenied {
							t.Fatalf("scoped grant exposed global resource: %v", err)
						}
					}
				})
			}
		})
	}
}
