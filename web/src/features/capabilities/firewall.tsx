// SPDX-License-Identifier: Apache-2.0

import { create, fromJsonString, toJsonString } from "@bufbuild/protobuf";
import { useId } from "react";
import {
  CapabilityFirewallSettingsSchema,
  type CapabilityFirewallSettings,
} from "../../../gen/lindm/agent/v1/capability_policy_pb";
import {
  ConnectivityGuardConfigSchema,
  ConnectivityProbeVerdict,
  type ConnectivityGuardConfig,
} from "../../../gen/lindm/agent/v1/connectivity_guard_pb";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { capabilityProblem } from "./validation";

// Editable deployment firewall settings. Every value stays text until it is
// turned into the exact protobuf the server validates.
export type FirewallDraft = {
  endpoints: { address: string; port: string }[];
  dnsServers: string;
  guard: string;
};

export function firewallDraft(settings: CapabilityFirewallSettings | undefined): FirewallDraft {
  return {
    endpoints: (settings?.managementEndpoints ?? []).map((endpoint) => ({
      address: endpoint.address,
      port: String(endpoint.port),
    })),
    dnsServers: (settings?.dnsServers ?? []).join("\n"),
    guard: settings?.connectivityGuard
      ? toJsonString(ConnectivityGuardConfigSchema, settings.connectivityGuard, { prettySpaces: 2 })
      : "",
  };
}

export type FirewallResult = {
  // Undefined when the draft is empty: the deployment has no firewall settings.
  settings?: CapabilityFirewallSettings;
  guard?: ConnectivityGuardConfig;
  // What still has to be provided before Firewall can be enabled, in words.
  missing: string[];
  problem: string;
};

export function parseFirewall(draft: FirewallDraft): FirewallResult {
  const endpoints = draft.endpoints.filter((row) => row.address.trim() || row.port.trim());
  const dnsServers = draft.dnsServers
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  const guardText = draft.guard.trim();
  const missing = [
    ...(endpoints.length ? [] : ["management addresses"]),
    ...(guardText ? [] : ["a connectivity check"]),
  ];
  if (!endpoints.length && !dnsServers.length && !guardText) return { missing, problem: "" };
  let guard: ConnectivityGuardConfig | undefined;
  if (guardText) {
    try {
      guard = fromJsonString(ConnectivityGuardConfigSchema, guardText);
    } catch (error) {
      return {
        missing,
        problem: `Invalid connectivity check: ${error instanceof Error ? error.message : "lindm could not read it"}.`,
      };
    }
  }
  const settings = create(CapabilityFirewallSettingsSchema, {
    managementEndpoints: endpoints.map((row) => ({
      address: row.address.trim(),
      port: /^\d+$/.test(row.port.trim()) ? Number(row.port.trim()) : 0,
    })),
    dnsServers,
    connectivityGuard: guard,
  });
  if (missing.length) return { settings, guard, missing, problem: "" };
  return {
    settings,
    guard,
    missing,
    problem: capabilityProblem(CapabilityFirewallSettingsSchema, settings),
  };
}

// What the pasted connectivity check does, so the administrator reads it back.
export function guardSummary(guard: ConnectivityGuardConfig): string {
  const allow = guard.probes.filter((probe) => probe.expected === ConnectivityProbeVerdict.ALLOW);
  const families = new Set(guard.probes.map((probe) => (probe.address.includes(":") ? 6 : 4)));
  return `The check uses ${guard.probes.length} probe targets over ${families.size === 2 ? "IPv4 and IPv6" : families.has(6) ? "IPv6 only" : "IPv4 only"}. It requires access to ${allow.length} targets and blocked access to ${guard.probes.length - allow.length} targets. The device reverses firewall changes after ${guard.timeoutSeconds ?? 120} seconds without confirmation.`;
}

export function FirewallSettingsFields({
  draft,
  onChange,
  result,
}: {
  draft: FirewallDraft;
  onChange: (draft: FirewallDraft) => void;
  result: FirewallResult;
}) {
  const id = useId();
  return (
    <fieldset className="grid min-w-0 gap-4 border p-4">
      <legend className="px-1 text-base font-semibold">Firewall settings for all devices</legend>
      <p className="text-sm text-muted-foreground">
        Set these values before enabling the firewall. Firewall changes preserve access to
        management addresses. The connectivity check reverses changes if the device loses contact.
      </p>
      <div className="grid gap-2">
        <span id={`${id}-endpoints`} className="text-sm font-medium">
          Management addresses
        </span>
        <p className="text-sm text-muted-foreground">
          Enter addresses and ports that devices must always reach, including this server and
          connectivity check peers.
        </p>
        {draft.endpoints.length === 0 ? (
          <p className="text-sm">No management addresses yet.</p>
        ) : null}
        <ul className="grid gap-2" aria-labelledby={`${id}-endpoints`}>
          {draft.endpoints.map((row, index) => (
            <li key={index} className="flex flex-wrap items-end gap-2">
              <label className="grid min-w-0 flex-1 basis-48 gap-1 text-sm">
                IP address
                <Input
                  data-freeform="management endpoint IP address"
                  inputMode="decimal"
                  value={row.address}
                  onChange={(event) =>
                    onChange({
                      ...draft,
                      endpoints: draft.endpoints.map((item, i) =>
                        i === index ? { ...item, address: event.target.value } : item,
                      ),
                    })
                  }
                />
              </label>
              <label className="grid w-28 gap-1 text-sm">
                Port
                <Input
                  data-freeform="management endpoint port"
                  inputMode="numeric"
                  value={row.port}
                  onChange={(event) =>
                    onChange({
                      ...draft,
                      endpoints: draft.endpoints.map((item, i) =>
                        i === index ? { ...item, port: event.target.value } : item,
                      ),
                    })
                  }
                />
              </label>
              <Button
                type="button"
                variant="outline"
                onClick={() =>
                  onChange({ ...draft, endpoints: draft.endpoints.filter((_, i) => i !== index) })
                }
              >
                Remove address {index + 1}
              </Button>
            </li>
          ))}
        </ul>
        <Button
          type="button"
          variant="outline"
          className="w-fit"
          disabled={draft.endpoints.length >= 32}
          onClick={() =>
            onChange({ ...draft, endpoints: [...draft.endpoints, { address: "", port: "443" }] })
          }
        >
          Add address
        </Button>
      </div>
      <label className="grid gap-2 text-sm font-medium">
        DNS servers (optional, one IP address per line)
        <Textarea
          data-freeform="DNS server addresses"
          rows={2}
          value={draft.dnsServers}
          onChange={(event) => onChange({ ...draft, dnsServers: event.target.value })}
        />
      </label>
      <div className="grid gap-2">
        <label htmlFor={`${id}-guard`} className="text-sm font-medium">
          Connectivity check
        </label>
        <p id={`${id}-guard-hint`} className="text-sm text-muted-foreground">
          Paste the connectivity check JSON from{" "}
          <code className="font-mono text-xs">/etc/lindm/executor.json</code>.
        </p>
        <Textarea
          id={`${id}-guard`}
          aria-describedby={`${id}-guard-hint ${id}-guard-status`}
          data-freeform="connectivity check JSON"
          className="font-mono text-xs"
          rows={6}
          spellCheck={false}
          value={draft.guard}
          onChange={(event) => onChange({ ...draft, guard: event.target.value })}
        />
        <p id={`${id}-guard-status`} className="text-sm" role="status">
          {result.guard ? guardSummary(result.guard) : null}
        </p>
      </div>
      {result.problem ? (
        <p role="alert" className="text-sm text-destructive">
          {result.problem}
        </p>
      ) : result.missing.length ? (
        <p className="text-sm text-warning">
          Add {result.missing.join(" and ")} before enabling the firewall.
        </p>
      ) : null}
    </fieldset>
  );
}
