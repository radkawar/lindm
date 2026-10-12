import { create } from "@bufbuild/protobuf";
import { useQueryClient } from "@tanstack/react-query";
import { useId, useState, type FormEvent, type ReactNode } from "react";
import {
  SetCapabilityPolicyRequestSchema,
  type CapabilityPolicy,
  type CapabilityPolicyScope,
  type SetCapabilityPolicyRequest,
} from "../../../gen/lindm/admin/v1/capabilities_pb";
import { ManagementCapability } from "../../../gen/lindm/agent/v1/management_capability_pb";
import { Button } from "@/components/ui/button";
import { RpcError } from "@/components/ui/rpc-error";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { useExactRequest } from "@/hooks/use-exact-request";
import { capabilityCopy, capabilityName, remoteCapabilities } from "@/lib/capabilities";
import { newRequestId } from "@/lib/ids";
import { reasonError, REASON_MAX_UNITS } from "@/lib/reason";
import { adminClient } from "@/lib/rpc";
import { FirewallSettingsFields, firewallDraft, parseFirewall } from "./firewall";
import { capabilityPoliciesQueryOptions } from "./queries";
import { capabilityProblem } from "./validation";

const SYSCTL_KEY = /^[a-z0-9_]+([.][a-zA-Z0-9_-]+)+$/;

// How many devices a scope reaches now, as " (3 devices now)", or nothing when
// the caller can't count it; composed by the route from the fleet and groups.
export type ScopeDevicesSlot = (props: { scope: CapabilityPolicyScope | undefined }) => ReactNode;

// Words for the devices a scope reaches, used in the consequence review.
export function scopeAudience(scope: CapabilityPolicyScope | undefined, name: string): string {
  switch (scope?.scope.case) {
    case "deployment":
      return "every enrolled device";
    case "staticGroupId":
      return `every device in the device group ${name || "(unnamed)"}`;
    case "dynamicGroupId":
      return `every device the dynamic group ${name || "(unnamed)"} matches`;
    default:
      return "the selected devices";
  }
}

function sysctlProblem(keys: string[]): string {
  if (keys.length > 128) return "List at most 128 kernel parameters.";
  const invalid = keys.find(
    (key) => !SYSCTL_KEY.test(key) || new TextEncoder().encode(key).length > 256,
  );
  if (invalid)
    return `"${invalid}" isn't a kernel parameter name. Use the dotted name, for example vm.swappiness.`;
  const repeated = keys.find((key, index) => keys.indexOf(key) !== index);
  if (repeated) return `"${repeated}" is listed twice.`;
  return "";
}

export function CapabilityPolicyEditor({
  policy,
  deploymentHasFirewall,
  issuanceUnavailable,
  scopeDevices: ScopeDevices,
  onClose,
  onSaved,
}: {
  // The scope's current policy; revision 0 for a group without one yet.
  policy: CapabilityPolicy;
  deploymentHasFirewall: boolean;
  issuanceUnavailable: boolean;
  scopeDevices: ScopeDevicesSlot;
  onClose: () => void;
  onSaved: (policy: CapabilityPolicy | undefined, removed: boolean) => void;
}) {
  const id = useId();
  const lifetime = useAuthLifetime();
  const client = useQueryClient();
  const deployment = policy.scope?.scope.case === "deployment";
  const [selected, setSelected] = useState<ManagementCapability[]>(() =>
    remoteCapabilities.filter((capability) => policy.capabilities.includes(capability)),
  );
  const [sysctl, setSysctl] = useState(policy.sysctlKeys.join("\n"));
  const [firewall, setFirewall] = useState(() => firewallDraft(policy.firewall));
  const [reason, setReason] = useState("");
  const request = useExactRequest<SetCapabilityPolicyRequest>();
  const disabled = request.busy || request.ambiguous;
  const parsedFirewall = deployment ? parseFirewall(firewall) : undefined;
  const firewallReady = deployment
    ? !!parsedFirewall?.settings && !parsedFirewall.missing.length
    : deploymentHasFirewall;
  const keys = sysctl
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  const turningOn = selected.filter((capability) => !policy.capabilities.includes(capability));
  const turningOff = policy.capabilities.filter((capability) => !selected.includes(capability));
  const removing = !deployment && policy.revision > 0n && selected.length === 0;
  const audience = scopeAudience(policy.scope, policy.scopeName);
  const conflict = request.failure?.reason === "capability_policy_revision_conflict";

  function toggle(capability: ManagementCapability, on: boolean) {
    setSelected(
      remoteCapabilities.filter((item) => (item === capability ? on : selected.includes(item))),
    );
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    void request.submit({
      capture: () => {
        const kernel = selected.includes(ManagementCapability.KERNEL_SETTINGS);
        if (kernel && keys.length === 0)
          throw new Error("List at least one kernel parameter, or turn Kernel settings off.");
        const keyProblem = kernel ? sysctlProblem(keys) : "";
        if (keyProblem) throw new Error(keyProblem);
        if (parsedFirewall?.problem) throw new Error(parsedFirewall.problem);
        if (selected.includes(ManagementCapability.FIREWALL) && !firewallReady)
          throw new Error(
            deployment
              ? `Firewall needs ${parsedFirewall?.missing.join(" and ")} first.`
              : "Firewall needs the firewall settings for all devices first.",
          );
        if (!selected.length && !removing && !deployment && policy.revision === 0n)
          throw new Error("Choose at least one capability for this group.");
        const problem = reasonError(reason);
        if (problem) throw new Error(problem);
        const value = create(SetCapabilityPolicyRequestSchema, {
          requestId: newRequestId(),
          scope: policy.scope,
          capabilities: selected,
          sysctlKeys: kernel ? keys : [],
          firewall: deployment ? parsedFirewall?.settings : undefined,
          expectedRevision: policy.revision,
          reason: reason.trim(),
        });
        const invalid = capabilityProblem(SetCapabilityPolicyRequestSchema, value);
        if (invalid) throw new Error(invalid);
        return value;
      },
      send: (value, options) => adminClient.setCapabilityPolicy(value, options),
      failureTitle: "Couldn't confirm the capability change",
      onSuccess: async (response) => {
        onSaved(response.policy, removing);
        await client.invalidateQueries({
          queryKey: capabilityPoliciesQueryOptions(lifetime).queryKey,
        });
        await client.invalidateQueries({ queryKey: ["device", lifetime.generation] });
      },
    });
  }

  return (
    <form className="grid min-w-0 gap-5" onSubmit={submit} aria-labelledby={`${id}-title`}>
      <h3 id={`${id}-title`} className="text-base font-semibold">
        {deployment
          ? "Edit capabilities for all devices"
          : `Edit capabilities for ${policy.scopeName || "this group"}`}
      </h3>
      <fieldset disabled={disabled} className="grid min-w-0 gap-5">
        <fieldset className="grid gap-3">
          <legend className="mb-2 text-sm font-medium">The lindm agent may manage</legend>
          {remoteCapabilities.map((capability) => {
            const copy = capabilityCopy(capability);
            const firewallBlocked =
              capability === ManagementCapability.FIREWALL &&
              !deployment &&
              !deploymentHasFirewall &&
              !selected.includes(capability);
            return (
              <label key={capability} className="flex items-start gap-2 text-sm">
                <input
                  type="checkbox"
                  className="mt-1"
                  checked={selected.includes(capability)}
                  disabled={firewallBlocked}
                  aria-describedby={`${id}-${capability}`}
                  onChange={(event) => toggle(capability, event.target.checked)}
                />
                <span className="grid gap-0.5">
                  <span className="font-medium">{copy.name}</span>
                  <span id={`${id}-${capability}`} className="text-muted-foreground">
                    {firewallBlocked
                      ? "Needs the firewall settings for all devices first (management endpoints and a connectivity check)."
                      : copy.description}
                  </span>
                </span>
              </label>
            );
          })}
        </fieldset>
        {selected.includes(ManagementCapability.KERNEL_SETTINGS) ? (
          <label className="grid gap-2 text-sm font-medium">
            Kernel parameters lindm may set (one per line, for example vm.swappiness)
            <Textarea
              data-freeform="kernel parameter names"
              className="font-mono text-xs"
              rows={4}
              spellCheck={false}
              value={sysctl}
              onChange={(event) => setSysctl(event.target.value)}
            />
            <span className="font-normal text-muted-foreground">
              The agent still refuses parameters that protect the system or lindm itself.
            </span>
          </label>
        ) : null}
        {deployment && parsedFirewall ? (
          <FirewallSettingsFields draft={firewall} onChange={setFirewall} result={parsedFirewall} />
        ) : null}
        <label className="grid gap-2 text-sm font-medium">
          Reason
          <Textarea
            data-freeform="audit reason"
            required
            maxLength={REASON_MAX_UNITS}
            value={reason}
            onChange={(event) => setReason(event.target.value)}
          />
          <span className="font-normal text-muted-foreground">Recorded in the audit log.</span>
        </label>
        <div className="grid gap-2 border border-warning p-4 text-sm">
          <h4 className="font-semibold">What happens when you save</h4>
          <p>
            {removing ? (
              <>
                This removes the group&apos;s policy. {audience[0].toUpperCase()}
                {audience.slice(1)}
                <ScopeDevices scope={policy.scope} /> keeps only what other policies allow.
              </>
            ) : turningOn.length || turningOff.length ? (
              <>
                For {audience}
                <ScopeDevices scope={policy.scope} />:{" "}
                {[
                  turningOn.length ? `turns on ${turningOn.map(capabilityName).join(", ")}` : "",
                  turningOff.length
                    ? `turns off ${turningOff.map(capabilityName).join(", ")} (unless another policy allows it)`
                    : "",
                ]
                  .filter(Boolean)
                  .join("; ")}
                .
              </>
            ) : (
              <>
                No capability changes for {audience}
                <ScopeDevices scope={policy.scope} />; only the settings below the list change.
              </>
            )}
          </p>
          <p>
            Devices get a newly signed policy at their next check-in. Profile items that need a
            capability that is off are blocked on those devices until it is on again.
          </p>
          {issuanceUnavailable ? (
            <p className="text-warning">
              The server can&apos;t sign capability policies right now, so this is saved but
              won&apos;t reach devices until the owner updates the execution delegation.
            </p>
          ) : null}
        </div>
      </fieldset>
      {request.invalid ? (
        <p role="alert" className="text-sm text-destructive">
          {request.invalid}
        </p>
      ) : null}
      {request.failure ? (
        <RpcError failure={request.failure}>
          {request.ambiguous ? (
            <p>The outcome is unknown. Retry only this same change; don&apos;t start another.</p>
          ) : null}
        </RpcError>
      ) : null}
      <div className="flex flex-wrap gap-2">
        {conflict ? (
          <Button type="button" onClick={onClose}>
            Close and reload policy
          </Button>
        ) : (
          <Button type="submit" disabled={request.busy}>
            {request.busy
              ? "Saving…"
              : request.ambiguous
                ? "Retry this change"
                : removing
                  ? "Remove group policy"
                  : "Save capabilities"}
          </Button>
        )}
        <Button type="button" variant="outline" disabled={disabled} onClick={onClose}>
          Cancel
        </Button>
        {request.ambiguous ? (
          <Button
            type="button"
            variant="outline"
            disabled={request.busy}
            onClick={() => {
              request.reset();
              onClose();
            }}
          >
            Stop and check current policy
          </Button>
        ) : null}
      </div>
    </form>
  );
}
