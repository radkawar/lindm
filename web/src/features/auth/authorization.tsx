import { clone, create } from "@bufbuild/protobuf";
import { queryOptions, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
import { SearchPicker, type PickerSlot } from "@/components/ui/search-picker";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { useExactRequest } from "@/hooks/use-exact-request";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { newRequestId } from "@/lib/ids";
import { permissionLabels } from "@/lib/permissions";
import { reasonError, REASON_MAX_UNITS } from "@/lib/reason";
import { adminClient } from "@/lib/rpc";
import { formatTimestamp } from "@/lib/time";
import {
  UpdateAuthorizationRequestSchema,
  type AuthorizationState,
  type UpdateAuthorizationRequest,
} from "../../../gen/lindm/admin/v1/authorization_pb";
import {
  AuthorizationPolicySchema,
  GroupBindingSchema,
  RoleDefinitionSchema,
  type DeviceScope,
} from "../../../gen/lindm/auth/v1/authorization_pb";
import { authorizationQueryOptions } from "./authorization-queries";
import { identitySettingsQueryOptions } from "./identity-settings";
import { normalizedScopes, ScopeEditor } from "./scope-editor";
import { sessionQueryKey } from "./queries";

const approvalPermissions = [
  "resources.assign",
  "execution_trust.manage",
  "remote_execution.run",
  "inventory.manage",
  "recovery_keys.read",
  "encryption.manage",
  "advisory_exceptions.manage",
  "actions.lock",
  "actions.release-lock",
  "actions.quarantine",
  "secrets.reveal",
];
const builtInRoles = ["owner", "admin", "operator", "helpdesk", "auditor"];

type Pickers = {
  devicePicker: PickerSlot;
  groupPicker: PickerSlot;
  directoryGroupPicker: PickerSlot;
};

export function Authorization(pickers: Pickers) {
  const lifetime = useAuthLifetime();
  const policy = useQuery(authorizationQueryOptions(lifetime));
  const identity = useQuery(identitySettingsQueryOptions(lifetime));
  const [editing, setEditing] = useState<AuthorizationState | null>(null);
  const [saved, setSaved] = useState<AuthorizationState | null>(null);
  return (
    <section className="grid min-w-0 gap-6">
      <PageHeader
        title="Authorization"
        description="Choose what administrators can do and which devices they can reach."
      />
      {policy.isPending || identity.isPending ? <p role="status">Loading access policy…</p> : null}
      {policy.isError ? <RpcError failure={toRpcFailure(policy.error)} /> : null}
      {identity.isError ? <RpcError failure={toRpcFailure(identity.error)} /> : null}
      {policy.data && !policy.data.authorization?.policy ? (
        <p role="alert">
          The access policy was not returned. Refresh before editing; no replacement policy has been
          assumed.
        </p>
      ) : null}
      {!editing ? (
        <Button
          className="w-fit"
          variant="outline"
          onClick={() => {
            void policy.refetch();
            void identity.refetch();
          }}
        >
          Refresh access policy
        </Button>
      ) : null}
      {saved ? (
        <div role="status" className="grid gap-2 border p-4">
          <p>
            Access policy saved. The recorded result below may be historical; refresh to see the
            current policy.
          </p>
          <TechnicalDetails
            items={[
              { label: "Saved revision", value: saved.revision.toString() },
              { label: "Saved at", value: formatTimestamp(saved.updatedAt).local },
            ]}
          />
        </div>
      ) : null}
      {policy.data?.authorization?.policy && identity.data && !identity.isError ? (
        editing ? (
          <AuthorizationEditor
            {...pickers}
            initial={editing}
            directoryPrimary={identity.data.primarySource !== "local"}
            onClose={() => setEditing(null)}
            onSaved={(state) => {
              setSaved(state);
              setEditing(null);
            }}
          />
        ) : (
          <div className="grid gap-4">
            <p className="text-sm text-muted-foreground">
              {policy.data.authorization.runtime ? "Runtime policy" : "Server bootstrap policy"}.
              Last changed: {formatTimestamp(policy.data.authorization.updatedAt).local}.
              {policy.isError ? " Current access could not be refreshed." : ""}
            </p>
            <Button
              className="w-fit"
              disabled={policy.isError || policy.isFetching}
              onClick={() => {
                setSaved(null);
                setEditing(policy.data!.authorization!);
              }}
            >
              Edit access policy
            </Button>
            <PolicySummary
              state={policy.data.authorization}
              primarySource={identity.data.primarySource}
            />
          </div>
        )
      ) : null}
    </section>
  );
}

function scopeDeviceQueryOptions(lifetime: AuthLifetime, deviceId: string) {
  return queryOptions({
    queryKey: ["device", lifetime.generation, deviceId],
    meta: { authGeneration: lifetime.generation },
    retry: false,
    queryFn: ({ signal }) =>
      adminClient.getDevice({ deviceId }, { signal: AbortSignal.any([signal, lifetime.signal]) }),
  });
}

function scopeGroupNamesQueryOptions(lifetime: AuthLifetime, groupIds: string[]) {
  return queryOptions({
    queryKey: ["authorization-scope-groups", lifetime.generation, groupIds],
    meta: { authGeneration: lifetime.generation },
    retry: false,
    enabled: groupIds.length > 0,
    queryFn: async ({ signal }) => {
      const combinedSignal = AbortSignal.any([signal, lifetime.signal]);
      const remaining = new Set(groupIds);
      const names: Record<string, string> = {};
      let pageToken = "";
      do {
        const response = await adminClient.listDeviceGroups(
          { pageSize: 100, pageToken },
          { signal: combinedSignal },
        );
        for (const group of response.groups) {
          if (remaining.delete(group.id)) names[group.id] = group.name;
        }
        pageToken = response.nextPageToken;
      } while (pageToken && remaining.size > 0);
      return names;
    },
  });
}

function ScopeDeviceName({ deviceId }: { deviceId: string }) {
  const lifetime = useAuthLifetime();
  const device = useQuery(scopeDeviceQueryOptions(lifetime, deviceId));
  return (
    <li className="min-w-0 break-words">
      {device.data?.device
        ? device.data.device.hostname.trim() || "Unnamed device"
        : device.isPending
          ? "Loading device name…"
          : "Device name unavailable"}
      {device.isError ? (
        <RpcError failure={toRpcFailure(device.error)}>
          <Button type="button" variant="outline" onClick={() => void device.refetch()}>
            Retry device name
          </Button>
        </RpcError>
      ) : null}
    </li>
  );
}

function ScopeSummary({
  scopes,
  groupNames,
  groupNamesPending,
}: {
  scopes: DeviceScope[];
  groupNames: Record<string, string>;
  groupNamesPending: boolean;
}) {
  if (!scopes.length) return <p className="text-sm">Device access: All devices.</p>;
  return (
    <div className="grid min-w-0 gap-2 text-sm">
      <p>Device access: Match any rule below; within a rule, all listed conditions must match.</p>
      <ol className="grid min-w-0 gap-3">
        {scopes.map((scope, index) => (
          <li key={index} className="grid min-w-0 gap-1 border-l-2 pl-3">
            <p className="font-medium">Rule {index + 1}</p>
            {!scope.labels.length && !scope.deviceIds.length && !scope.groupIds.length ? (
              <p>All devices.</p>
            ) : null}
            {scope.labels.length ? (
              <p className="min-w-0 break-words">All labels: {scope.labels.join(", ")}</p>
            ) : null}
            {scope.deviceIds.length ? (
              <div className="min-w-0">
                <p className="text-muted-foreground">Any of these devices:</p>
                <ul className="min-w-0 list-inside list-disc">
                  {scope.deviceIds.map((deviceId) => (
                    <ScopeDeviceName key={deviceId} deviceId={deviceId} />
                  ))}
                </ul>
              </div>
            ) : null}
            {scope.groupIds.length ? (
              <p className="min-w-0 break-words">
                Any device group:{" "}
                {scope.groupIds
                  .map(
                    (id) =>
                      groupNames[id] ||
                      (groupNamesPending ? "Loading group name…" : "Device group name unavailable"),
                  )
                  .join(", ")}
              </p>
            ) : null}
            <TechnicalDetails
              items={[
                { label: "Device references", value: scope.deviceIds.join(", ") },
                { label: "Device group references", value: scope.groupIds.join(", ") },
              ]}
            />
          </li>
        ))}
      </ol>
    </div>
  );
}

function PolicySummary({
  state,
  primarySource,
}: {
  state: AuthorizationState;
  primarySource: string;
}) {
  const policy = state.policy;
  const lifetime = useAuthLifetime();
  const groupIds = [
    ...new Set(
      policy?.groupBindings.flatMap((binding) => binding.scopes.flatMap((scope) => scope.groupIds)),
    ),
  ].sort();
  const groupNames = useQuery(scopeGroupNamesQueryOptions(lifetime, groupIds));
  return (
    <div className="grid min-w-0 gap-6">
      <section className="grid min-w-0 gap-3" aria-label="Custom roles">
        <h2 className="text-base font-semibold">Custom roles</h2>
        {!policy?.roles.length ? <p>No custom roles. Built-in roles remain available.</p> : null}
        {policy?.roles.map((role) => (
          <div key={role.name} className="min-w-0 border-b pb-3">
            <h3 className="font-medium break-words">{role.name}</h3>
            <p className="text-sm">
              {role.permissions
                .map((permission) => permissionLabels[permission] ?? "Unrecognized permission")
                .join(", ")}
            </p>
          </div>
        ))}
      </section>
      <section className="grid min-w-0 gap-3" aria-label="Directory access">
        <h2 className="text-base font-semibold">Directory access</h2>
        {!policy?.groupBindings.length ? (
          <p>No directory groups grant access through this policy.</p>
        ) : null}
        {groupNames.isError ? (
          <RpcError failure={toRpcFailure(groupNames.error)}>
            <Button type="button" variant="outline" onClick={() => void groupNames.refetch()}>
              Retry group names
            </Button>
          </RpcError>
        ) : null}
        {policy?.groupBindings.map((binding, index) => (
          <div key={index} className="grid min-w-0 gap-2 border-b pb-3">
            <h3 className="min-w-0 font-medium break-words">
              {primarySource === "keycloak" ? binding.group : `Directory group ${index + 1}`}
            </h3>
            <p className="text-sm">Role: {binding.role}</p>
            {primarySource !== "keycloak" ? (
              <p className="text-sm text-muted-foreground">
                Display name unavailable from the identity provider.
              </p>
            ) : null}
            <ScopeSummary
              scopes={binding.scopes}
              groupNames={groupNames.data ?? {}}
              groupNamesPending={groupNames.isPending}
            />
            <TechnicalDetails
              items={[{ label: "Directory group reference", value: binding.group }]}
            />
          </div>
        ))}
      </section>
      <section className="grid min-w-0 gap-3" aria-label="Independent approval">
        <h2 className="text-base font-semibold">Independent approval</h2>
        <p>
          {policy?.approvalRequiredPermissions.length
            ? policy.approvalRequiredPermissions
                .map((permission) => permissionLabels[permission] ?? "Unrecognized permission")
                .join(", ")
            : "No additional operations require independent approval under this policy."}
        </p>
      </section>
      <TechnicalDetails items={[{ label: "Revision", value: state.revision.toString() }]} />
    </div>
  );
}

function PermissionPicker({
  label,
  values,
  choices,
  onChange,
}: {
  label: string;
  values: string[];
  choices: string[];
  onChange: (values: string[]) => void;
}) {
  return (
    <fieldset className="grid gap-2">
      <legend className="mb-2 text-sm font-medium">{label}</legend>
      <div className="grid gap-2 sm:grid-cols-2">
        {choices.map((permission) => (
          <label key={permission} className="flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={values.includes(permission)}
              onChange={(event) =>
                onChange(
                  event.target.checked
                    ? [...values, permission]
                    : values.filter((value) => value !== permission),
                )
              }
            />
            {permissionLabels[permission]}
          </label>
        ))}
      </div>
    </fieldset>
  );
}

function AuthorizationEditor({
  initial,
  directoryPrimary,
  devicePicker,
  groupPicker,
  directoryGroupPicker: DirectoryGroupPicker,
  onClose,
  onSaved,
}: Pickers & {
  initial: AuthorizationState;
  directoryPrimary: boolean;
  onClose: () => void;
  onSaved: (state: AuthorizationState) => void;
}) {
  const lifetime = useAuthLifetime();
  const client = useQueryClient();
  const [policy, setDraft] = useState(() => clone(AuthorizationPolicySchema, initial.policy!));
  const [reason, setReason] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const request = useExactRequest<UpdateAuthorizationRequest>();
  const disabled = request.busy || request.ambiguous;
  function setPolicy(value: typeof policy) {
    setDraft(value);
    setConfirmed(false);
  }
  function submit(event: FormEvent) {
    event.preventDefault();
    void request.submit({
      capture: () => {
        const problem = reasonError(reason);
        if (problem) throw new Error(problem);
        if (!confirmed) throw new Error("Confirm the access consequences before saving.");
        return create(UpdateAuthorizationRequestSchema, {
          requestId: newRequestId(),
          expectedRevision: initial.revision,
          reason,
          policy: create(AuthorizationPolicySchema, {
            ...policy,
            groupBindings: policy.groupBindings.map((binding) => ({
              ...binding,
              scopes: normalizedScopes(binding.scopes),
            })),
          }),
        });
      },
      send: (value, options) => adminClient.updateAuthorization(value, options),
      failureTitle: "Couldn't confirm the access policy",
      onSuccess: async (response) => {
        if (!response.authorization) throw new Error("The saved access policy was not returned.");
        onSaved(response.authorization);
        await client.invalidateQueries({ queryKey: authorizationQueryOptions(lifetime).queryKey });
        await client.invalidateQueries({ queryKey: ["local-accounts", lifetime.generation] });
        await client.invalidateQueries({ queryKey: sessionQueryKey });
      },
    });
  }
  return (
    <form className="grid gap-6" onSubmit={submit}>
      <fieldset disabled={disabled} className="grid min-w-0 gap-6">
        <legend className="mb-4 text-base font-semibold">Edit access policy</legend>
        <section className="grid gap-4" aria-label="Edit custom roles">
          <h2 className="text-base font-semibold">Custom roles</h2>
          {policy.roles.map((role, index) => (
            <div className="grid min-w-0 gap-4 border p-4" key={index}>
              <label className="grid gap-2 text-sm font-medium">
                Role name
                <Input
                  data-freeform="new custom role name"
                  required
                  maxLength={64}
                  pattern="[a-z][a-z0-9_.-]*"
                  value={role.name}
                  onChange={(event) =>
                    setPolicy({
                      ...policy,
                      roles: policy.roles.map((item, i) =>
                        i === index ? { ...item, name: event.target.value } : item,
                      ),
                    })
                  }
                />
              </label>
              <PermissionPicker
                label="Allowed operations"
                choices={Object.keys(permissionLabels)}
                values={role.permissions}
                onChange={(permissions) =>
                  setPolicy({
                    ...policy,
                    roles: policy.roles.map((item, i) =>
                      i === index ? { ...item, permissions } : item,
                    ),
                  })
                }
              />
              <Button
                type="button"
                variant="outline"
                className="w-fit"
                onClick={() =>
                  setPolicy({ ...policy, roles: policy.roles.filter((_, i) => i !== index) })
                }
              >
                Remove role {role.name || index + 1}
              </Button>
            </div>
          ))}
          <Button
            type="button"
            className="w-fit"
            variant="outline"
            disabled={disabled || policy.roles.length >= 100}
            onClick={() =>
              setPolicy({ ...policy, roles: [...policy.roles, create(RoleDefinitionSchema)] })
            }
          >
            Add custom role
          </Button>
        </section>
        <section className="grid gap-4" aria-label="Edit directory access">
          <h2 className="text-base font-semibold">Directory group access</h2>
          {!directoryPrimary ? (
            <p className="text-sm">
              Local sign-in does not allow directory group bindings. Assign roles and device access
              to local accounts on Accounts.
            </p>
          ) : (
            <>
              {policy.groupBindings.map((binding, index) => (
                <div className="grid min-w-0 gap-4 border p-4" key={index}>
                  <DirectoryGroupPicker
                    label={`Directory group ${index + 1}`}
                    value={binding.group}
                    disabled={disabled}
                    onChange={(group) =>
                      setPolicy({
                        ...policy,
                        groupBindings: policy.groupBindings.map((item, i) =>
                          i === index ? { ...item, group } : item,
                        ),
                      })
                    }
                  />
                  <SearchPicker
                    label="Role"
                    value={binding.role}
                    disabled={disabled}
                    options={[...builtInRoles, ...policy.roles.map((role) => role.name)]
                      .filter(Boolean)
                      .map((role) => ({ value: role, label: role }))}
                    onChange={(role) =>
                      setPolicy({
                        ...policy,
                        groupBindings: policy.groupBindings.map((item, i) =>
                          i === index ? { ...item, role } : item,
                        ),
                      })
                    }
                  />
                  <ScopeEditor
                    scopes={binding.scopes}
                    disabled={disabled}
                    devicePicker={devicePicker}
                    groupPicker={groupPicker}
                    onChange={(scopes) =>
                      setPolicy({
                        ...policy,
                        groupBindings: policy.groupBindings.map((item, i) =>
                          i === index ? { ...item, scopes } : item,
                        ),
                      })
                    }
                  />
                  <Button
                    type="button"
                    variant="outline"
                    className="w-fit"
                    onClick={() =>
                      setPolicy({
                        ...policy,
                        groupBindings: policy.groupBindings.filter((_, i) => i !== index),
                      })
                    }
                  >
                    Remove binding {index + 1}
                  </Button>
                </div>
              ))}
              <Button
                type="button"
                variant="outline"
                className="w-fit"
                disabled={disabled || policy.groupBindings.length >= 1000}
                onClick={() =>
                  setPolicy({
                    ...policy,
                    groupBindings: [...policy.groupBindings, create(GroupBindingSchema)],
                  })
                }
              >
                Add directory group access
              </Button>
            </>
          )}
        </section>
        <PermissionPicker
          label="Require independent approval"
          choices={approvalPermissions}
          values={policy.approvalRequiredPermissions}
          onChange={(approvalRequiredPermissions) =>
            setPolicy({ ...policy, approvalRequiredPermissions })
          }
        />
        <label className="grid gap-2 text-sm font-medium">
          Reason
          <Textarea
            data-freeform="audit reason"
            required
            maxLength={REASON_MAX_UNITS}
            value={reason}
            onChange={(event) => setReason(event.target.value)}
          />
        </label>
        <div className="grid gap-3 border border-warning p-4 text-sm">
          <h2 className="font-semibold">Review the access change</h2>
          <p>
            This replaces the complete policy: {policy.roles.length} custom roles,{" "}
            {policy.groupBindings.length} directory group bindings and{" "}
            {policy.approvalRequiredPermissions.length} approval requirements. Removed grants stop
            authorizing work; unscoped bindings allow every device.
          </p>
          <p>
            Non-owner sessions are signed out and pending authority is invalidated. Local
            unrestricted owners and the deployment owner retain recovery access. Account roles are
            not reassigned when you remove or rename a role.
          </p>
          <label className="flex items-start gap-2">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(event) => setConfirmed(event.target.checked)}
            />
            I reviewed the complete access policy and sign-out consequences.
          </label>
        </div>
      </fieldset>
      {request.invalid ? <p role="alert">{request.invalid}</p> : null}
      {request.failure ? (
        <RpcError failure={request.failure}>
          <p>
            {request.ambiguous
              ? "The outcome is unknown. Retry only this exact change; do not start another policy update."
              : "If another administrator changed the policy, close this editor and refresh before editing again."}
          </p>
        </RpcError>
      ) : null}
      <div className="flex flex-wrap gap-2">
        <Button type="submit" disabled={request.busy || (!request.ambiguous && !confirmed)}>
          {request.busy
            ? "Saving…"
            : request.ambiguous
              ? "Retry exact access change"
              : "Save access policy"}
        </Button>
        <Button type="button" variant="outline" disabled={disabled} onClick={onClose}>
          Cancel editing
        </Button>
      </div>
    </form>
  );
}
