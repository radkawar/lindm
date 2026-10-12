import { Timestamp } from "@/components/ui/timestamp";
import { queryOptions, useQuery } from "@tanstack/react-query";
import { RpcError } from "@/components/ui/rpc-error";
import { StatusBadge } from "@/components/ui/status-badge";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { fetchIdentitySettings } from "./local-api";

export function identitySettingsQueryOptions(lifetime: AuthLifetime) {
  return queryOptions({
    queryKey: ["identity-settings", lifetime.generation],
    meta: { authGeneration: lifetime.generation },
    queryFn: ({ signal }) => fetchIdentitySettings(AbortSignal.any([signal, lifetime.signal])),
    refetchInterval: 30_000,
    retry: false,
  });
}

export function IdentitySettings() {
  const lifetime = useAuthLifetime();
  const query = useQuery(identitySettingsQueryOptions(lifetime));
  const settings = query.data;
  return (
    <section className="grid gap-3 border p-4 sm:p-6" aria-labelledby="identity-settings-heading">
      <h2 id="identity-settings-heading" className="text-base font-semibold">
        Sign-in source
      </h2>
      <p className="text-sm text-muted-foreground">
        Set in the server configuration. You can't change it here.
      </p>
      {query.isPending ? <p role="status">Loading identity settings…</p> : null}
      {query.isError ? <RpcError failure={toRpcFailure(query.error)} /> : null}
      {settings && !query.isError ? (
        <>
          <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-[14rem_minmax(0,1fr)] [&_dt]:text-muted-foreground">
            <dt>Sign-in provider</dt>
            <dd>{sourceLabel(settings.primarySource)}</dd>
            {settings.brokerEnabled ? (
              <>
                <dt>Upstream provider</dt>
                <dd>{settings.upstreamSource || "Not reported"}</dd>
                <dt>SCIM provisioning</dt>
                <dd>
                  <StatusBadge status={settings.scimEnabled ? "info" : "neutral"}>
                    {settings.scimEnabled ? "On (removes access only)" : "Not configured"}
                  </StatusBadge>
                </dd>
              </>
            ) : null}
            <dt>Local emergency sign-in</dt>
            <dd>
              <StatusBadge status={settings.breakGlassEnabled ? "warning" : "neutral"}>
                {settings.breakGlassEnabled ? "Configured" : "Not configured"}
              </StatusBadge>
            </dd>
            {settings.refreshIntervalSeconds ? (
              <>
                <dt>Access recheck</dt>
                <dd>
                  Every {durationLabel(settings.refreshIntervalSeconds)}; access stops if no recheck
                  succeeds for {durationLabel(settings.maxSnapshotAgeSeconds)}
                </dd>
              </>
            ) : null}
            <dt>Your access</dt>
            <dd>
              <StatusBadge
                status={settings.localAuthority || settings.current ? "success" : "warning"}
              >
                {settings.localAuthority
                  ? "Current (local account)"
                  : settings.current
                    ? "Current"
                    : "Needs recheck"}
              </StatusBadge>
            </dd>
            {settings.observedAt || !settings.localAuthority ? (
              <>
                <dt>Last checked</dt>
                <dd>
                  <Timestamp value={settings.observedAt} missing="Not checked yet" />
                </dd>
              </>
            ) : null}
          </dl>
          {settings.refreshIntervalSeconds ? (
            <p className="text-sm text-muted-foreground">
              This is about your own account. If the check fails or is too old, you lose access
              until it succeeds.
            </p>
          ) : null}
          <TechnicalDetails
            items={[
              { label: "Issuer", value: settings.issuer },
              { label: "Sign-in source", value: settings.primarySource },
            ]}
          />
        </>
      ) : null}
    </section>
  );
}

function sourceLabel(source: string): string {
  if (source === "local") return "Local accounts on this server";
  if (source === "keycloak") return "Keycloak";
  return source || "Not reported";
}

function durationLabel(seconds: number): string {
  if (seconds < 120) return `${seconds} seconds`;
  if (seconds < 7200) return `${Math.round(seconds / 60)} minutes`;
  return `${Math.round(seconds / 3600)} hours`;
}
