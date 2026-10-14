// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import {
  CapabilityPolicySchema,
  type CapabilityPolicy,
  type CapabilityPolicyScope,
} from "../../../gen/lindm/admin/v1/capabilities_pb";
import { ManagementCapability } from "../../../gen/lindm/agent/v1/management_capability_pb";
import { Button } from "@/components/ui/button";
import { CapabilityIssuanceAlert } from "@/components/ui/capability-issuance";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
import type { PickerSlot } from "@/components/ui/search-picker";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import { StatusBadge } from "@/components/ui/status-badge";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { Timestamp } from "@/components/ui/timestamp";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import {
  CAPABILITIES_PATH,
  capabilityCopy,
  capabilityName,
  localCapabilities,
  localCapabilityField,
  remoteCapabilities,
} from "@/lib/capabilities";
import { toRpcFailure } from "@/lib/errors";
import { canPermission } from "@/lib/permissions";
import { CapabilityPolicyEditor, type ScopeDevicesSlot } from "./editor";
import { firewallDraft, guardSummary, parseFirewall } from "./firewall";
import { capabilityPoliciesQueryOptions } from "./queries";

type Editing = { key: string; policy: CapabilityPolicy };

function scopeKey(scope: CapabilityPolicyScope | undefined): string {
  return `${scope?.scope.case ?? "none"}:${String(scope?.scope.value ?? "")}`;
}

const plural = (count: number, noun: string) => `${count} ${noun}${count === 1 ? "" : "s"}`;

function changedBy(policy: CapabilityPolicy) {
  if (policy.revision === 0n) return <>Not set yet.</>;
  if (!policy.updatedBy)
    return (
      <>
        Install default, set <Timestamp value={policy.updatedAt} />.
      </>
    );
  return (
    <>
      Last changed by {policy.updatedBy} <Timestamp value={policy.updatedAt} />.
    </>
  );
}

export function DeviceCapabilitiesView({
  groupPicker: GroupPicker,
  dynamicGroupPicker: DynamicGroupPicker,
  scopeDevices,
}: {
  groupPicker: PickerSlot;
  dynamicGroupPicker: PickerSlot;
  scopeDevices: ScopeDevicesSlot;
}) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const client = useQueryClient();
  const query = useQuery(capabilityPoliciesQueryOptions(lifetime));
  const canManage = canPermission(principal, "execution_trust.manage", true);
  const [editing, setEditing] = useState<Editing | null>(null);
  const [saved, setSaved] = useState("");
  const [adding, setAdding] = useState<"staticGroupId" | "dynamicGroupId" | null>(null);
  const [addGroup, setAddGroup] = useState("");
  const data = query.data;
  const deployment = data?.deployment;
  const deploymentHasFirewall = !!deployment?.firewall;
  const refresh = () =>
    void client.invalidateQueries({ queryKey: capabilityPoliciesQueryOptions(lifetime).queryKey });

  function edit(policy: CapabilityPolicy) {
    setSaved("");
    setAdding(null);
    setEditing({ key: scopeKey(policy.scope), policy });
  }

  function editor(policy: CapabilityPolicy) {
    return (
      <CapabilityPolicyEditor
        policy={policy}
        deploymentHasFirewall={deploymentHasFirewall}
        issuanceUnavailable={!!data?.issuanceUnavailableReason}
        scopeDevices={scopeDevices}
        onClose={() => {
          setEditing(null);
          refresh();
        }}
        onSaved={(_, removed) => {
          setEditing(null);
          setSaved(
            removed
              ? "Group policy removed. Devices get the change at their next check-in."
              : "Capabilities saved. Devices get the change at their next check-in.",
          );
        }}
      />
    );
  }

  return (
    <div className="grid min-w-0 gap-6" data-review-page="device-capabilities">
      <PageHeader
        title="Device capabilities"
        description="Choose which changes the agent can make. Devices receive permissions from the policy for all devices and their group policies."
        onRefresh={editing ? undefined : refresh}
        refreshing={query.isFetching}
      />
      {query.isPending ? <p role="status">Loading capability policies…</p> : null}
      {query.isError ? (
        <RpcError failure={toRpcFailure(query.error)} title="Couldn't load capability policies">
          {data ? <p>The policies below do not include a confirmed update.</p> : null}
        </RpcError>
      ) : null}
      {saved ? (
        <p role="status" className="text-sm">
          {saved}
        </p>
      ) : null}
      {data ? (
        <>
          <CapabilityIssuanceAlert reason={data.issuanceUnavailableReason} />
          {!canManage ? (
            <p className="text-sm text-muted-foreground">
              You need permission to change trusted signing keys for all devices.
            </p>
          ) : null}
          <section className="grid min-w-0 gap-3 border-t pt-4" aria-labelledby="all-devices">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="grid gap-1">
                <h2 id="all-devices" className="text-base font-semibold">
                  All devices
                </h2>
                {deployment ? (
                  <p className="text-sm text-muted-foreground">{changedBy(deployment)}</p>
                ) : null}
              </div>
              {/* One editor at a time: other scopes' Edit buttons return when it closes. */}
              {canManage && deployment && editing === null ? (
                <Button variant="outline" onClick={() => edit(deployment)}>
                  Edit all devices
                </Button>
              ) : null}
            </div>
            {!deployment ? (
              <p role="alert">
                The server did not return the policy for all devices. Refresh before editing.
              </p>
            ) : editing?.key === scopeKey(deployment.scope) ? (
              editor(editing.policy)
            ) : (
              <PolicyCapabilities policy={deployment} deployment />
            )}
          </section>
          <section className="grid min-w-0 gap-3 border-t pt-4" aria-labelledby="group-policies">
            <div className="grid gap-1">
              <h2 id="group-policies" className="text-base font-semibold">
                Groups
              </h2>
              <p className="text-sm text-muted-foreground">
                Allow more on the devices in a device group or a dynamic group.
              </p>
            </div>
            {data.groups.length === 0 ? (
              <p className="text-sm">No group allows more than all devices.</p>
            ) : (
              <ul className="grid min-w-0 gap-3">
                {data.groups.map((policy) => {
                  const key = scopeKey(policy.scope);
                  return (
                    <li key={key} className="grid min-w-0 gap-2 border-b pb-3">
                      {editing?.key === key ? (
                        editor(editing.policy)
                      ) : (
                        <>
                          <div className="flex flex-wrap items-start justify-between gap-3">
                            <div className="grid min-w-0 gap-1">
                              <h3 className="break-words font-medium">
                                {policy.scopeName || "Unnamed group"}
                              </h3>
                              <p className="text-sm text-muted-foreground">
                                {policy.scope?.scope.case === "dynamicGroupId"
                                  ? "Dynamic group"
                                  : "Device group"}
                                . {changedBy(policy)}
                              </p>
                            </div>
                            {canManage && editing === null ? (
                              <Button variant="outline" onClick={() => edit(policy)}>
                                Edit {policy.scopeName || "group"}
                              </Button>
                            ) : null}
                          </div>
                          <PolicyCapabilities policy={policy} />
                          <TechnicalDetails
                            items={[
                              {
                                label: "Group reference",
                                value: String(policy.scope?.scope.value ?? ""),
                              },
                              { label: "Revision", value: policy.revision.toString() },
                            ]}
                          />
                        </>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
            {canManage && editing === null ? (
              adding ? (
                <div className="grid max-w-xl gap-3 border p-4">
                  <Label htmlFor="capability-group-kind">Group type</Label>
                  <SelectField
                    id="capability-group-kind"
                    value={adding}
                    onValueChange={(value) => {
                      setAdding(value as "staticGroupId" | "dynamicGroupId");
                      setAddGroup("");
                    }}
                    options={[
                      { value: "staticGroupId", label: "Device group" },
                      { value: "dynamicGroupId", label: "Dynamic group" },
                    ]}
                  />
                  {adding === "staticGroupId" ? (
                    <GroupPicker label="Device group" value={addGroup} onChange={setAddGroup} />
                  ) : (
                    <DynamicGroupPicker
                      label="Dynamic group"
                      value={addGroup}
                      onChange={setAddGroup}
                    />
                  )}
                  <div className="flex flex-wrap gap-2">
                    <Button
                      disabled={!addGroup}
                      aria-describedby={addGroup ? undefined : "capability-group-hint"}
                      onClick={() => {
                        const existing = data.groups.find(
                          (policy) =>
                            policy.scope?.scope.case === adding &&
                            policy.scope.scope.value === addGroup,
                        );
                        edit(
                          existing ??
                            create(CapabilityPolicySchema, {
                              scope: { scope: { case: adding, value: addGroup } },
                            }),
                        );
                      }}
                    >
                      Choose capabilities
                    </Button>
                    <Button variant="outline" onClick={() => setAdding(null)}>
                      Cancel
                    </Button>
                  </div>
                  {!addGroup ? (
                    <p id="capability-group-hint" className="text-sm text-muted-foreground">
                      Choose a group first.
                    </p>
                  ) : null}
                </div>
              ) : (
                <Button
                  variant="outline"
                  className="w-fit"
                  onClick={() => {
                    setSaved("");
                    setAddGroup("");
                    setAdding("staticGroupId");
                  }}
                >
                  Allow more for a group
                </Button>
              )
            ) : null}
            {editing &&
            !data.groups.some((policy) => scopeKey(policy.scope) === editing.key) &&
            editing.key !== scopeKey(deployment?.scope)
              ? editor(editing.policy)
              : null}
          </section>
          <section className="grid min-w-0 gap-3 border-t pt-4" aria-labelledby="device-only">
            <div className="grid gap-1">
              <h2 id="device-only" className="text-base font-semibold">
                Set on the device only
              </h2>
              <p className="text-sm text-muted-foreground">
                lindm never grants these remotely. Root on the device sets them in{" "}
                <code className="font-mono text-xs">/etc/lindm/executor.json</code>.
              </p>
            </div>
            <ul className="grid gap-2 text-sm">
              {localCapabilities.map((capability) => (
                <li key={capability} className="grid gap-0.5">
                  <span className="font-medium">{capabilityName(capability)}</span>
                  <span className="text-muted-foreground">
                    {capabilityCopy(capability).description} Set{" "}
                    <code className="font-mono text-xs">{localCapabilityField[capability]}</code> on
                    the device.
                  </span>
                </li>
              ))}
            </ul>
          </section>
          <TechnicalDetails
            items={[
              { label: "Signing unavailable reason", value: data.issuanceUnavailableReason },
              { label: "All devices revision", value: deployment?.revision.toString() },
            ]}
          />
        </>
      ) : null}
    </div>
  );
}

// One policy's capabilities, in catalogue order, with what each one still needs.
function PolicyCapabilities({
  policy,
  deployment = false,
}: {
  policy: CapabilityPolicy;
  deployment?: boolean;
}) {
  const firewall = deployment ? parseFirewall(firewallDraft(policy.firewall)) : undefined;
  const shown = deployment
    ? remoteCapabilities
    : remoteCapabilities.filter((capability) => policy.capabilities.includes(capability));
  return (
    <ul className="grid min-w-0 gap-2 text-sm">
      {shown.map((capability) => {
        const on = policy.capabilities.includes(capability);
        return (
          <li key={capability} className="flex min-w-0 flex-wrap items-start gap-x-3 gap-y-1">
            <StatusBadge status={on ? "success" : "neutral"} className="w-20 justify-center">
              {on ? "Allowed" : "Off"}
            </StatusBadge>
            <span className="grid min-w-0 flex-1 basis-60 gap-0.5">
              <span className="font-medium">{capabilityName(capability)}</span>
              <span className="text-muted-foreground">
                {capabilityCopy(capability).description}
              </span>
              {capability === ManagementCapability.KERNEL_SETTINGS && on ? (
                // Parameter names are long unbroken tokens; anywhere-wrapping
                // keeps their min-content inside a 375px viewport.
                <span className="[overflow-wrap:anywhere]">
                  Parameters:{" "}
                  {policy.sysctlKeys.map((key, index) => (
                    <span key={key}>
                      {index ? ", " : ""}
                      <code className="font-mono text-xs">{key}</code>
                    </span>
                  ))}
                </span>
              ) : null}
              {capability === ManagementCapability.FIREWALL && firewall ? (
                firewall.missing.length ? (
                  <span className="text-warning">
                    Add {firewall.missing.join(" and ")} to the policy for all devices before
                    enabling the firewall.
                  </span>
                ) : (
                  <span>
                    {[
                      plural(
                        policy.firewall?.managementEndpoints.length ?? 0,
                        "management address",
                      ),
                      policy.firewall?.dnsServers.length
                        ? plural(policy.firewall.dnsServers.length, "DNS server")
                        : "",
                    ]
                      .filter(Boolean)
                      .join(", ")}
                    . {firewall.guard ? guardSummary(firewall.guard) : null}
                  </span>
                )
              ) : null}
            </span>
          </li>
        );
      })}
    </ul>
  );
}

// The Settings index entry for this page.
export function DeviceCapabilitiesSettingsSection() {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const canRead = canPermission(principal, "fleet.read", true);
  const query = useQuery({ ...capabilityPoliciesQueryOptions(lifetime), enabled: canRead });
  if (!canRead) return null;
  const deployment = query.data?.deployment;
  return (
    <section className="grid min-w-0 gap-2 border-t pt-4" aria-labelledby="device-capabilities">
      <h2 id="device-capabilities" className="text-base font-semibold">
        Device capabilities
      </h2>
      {query.isError ? <RpcError failure={toRpcFailure(query.error)} /> : null}
      {query.isPending ? <p role="status">Loading capability policies…</p> : null}
      {query.data ? (
        <p className="text-sm">
          All devices allow{" "}
          {deployment?.capabilities.length
            ? deployment.capabilities.map(capabilityName).join(", ")
            : "nothing yet"}
          .{" "}
          {query.data.groups.length
            ? `${plural(query.data.groups.length, "group")} allow${query.data.groups.length === 1 ? "s" : ""} more.`
            : "No group allows more."}
          {query.data.issuanceUnavailableReason
            ? " Devices aren't receiving capability changes until the owner updates the execution delegation."
            : ""}
        </p>
      ) : null}
      <Link to={CAPABILITIES_PATH} className="w-fit text-sm underline underline-offset-4">
        Review device capabilities
      </Link>
    </section>
  );
}

// A capability source on the device page, read after "Allowed for", named from
// the policies list when the caller may read it.
export function CapabilityScopeName({ scope }: { scope: CapabilityPolicyScope }) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const query = useQuery({
    ...capabilityPoliciesQueryOptions(lifetime),
    enabled: canPermission(principal, "fleet.read", true) && scope.scope.case !== "deployment",
  });
  if (scope.scope.case === "deployment") return <>all devices</>;
  const name = query.data?.groups.find(
    (policy) => scopeKey(policy.scope) === scopeKey(scope),
  )?.scopeName;
  const kind = scope.scope.case === "dynamicGroupId" ? "dynamic group" : "device group";
  if (name) return <>{`${name} (${kind})`}</>;
  return (
    <>{query.isPending && query.fetchStatus !== "idle" ? `Loading ${kind} name…` : `a ${kind}`}</>
  );
}
