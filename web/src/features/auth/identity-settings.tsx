import { timestampDate } from "@bufbuild/protobuf/wkt";
import { queryOptions, useQuery } from "@tanstack/react-query";
import { RpcError } from "@/components/ui/rpc-error";
import { StatusBadge } from "@/components/ui/status-badge";
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
    <section className="grid gap-3 rounded border p-4" aria-label="Identity settings">
      <h2 className="text-lg font-semibold">Configured identity source</h2>
      <p>
        Read-only deployment configuration. Change identity connectors in the server configuration.
      </p>
      {query.isPending ? <p role="status">Loading identity settings…</p> : null}
      {query.isError ? <RpcError failure={toRpcFailure(query.error)} /> : null}
      {settings && !query.isError ? (
        <>
          <dl className="grid gap-2 sm:grid-cols-2">
            <dt>Primary source</dt>
            <dd>{settings.primarySource}</dd>
            <dt>Issuer</dt>
            <dd className="break-all">{settings.issuer}</dd>
            <dt>Broker upstream</dt>
            <dd>{settings.brokerEnabled ? settings.upstreamSource : "Not configured"}</dd>
            <dt>SCIM provisioning</dt>
            <dd>
              <StatusBadge status={settings.scimEnabled ? "info" : "neutral"}>
                {settings.scimEnabled ? "Enabled (revocation only)" : "Not configured"}
              </StatusBadge>
            </dd>
            <dt>Local break-glass</dt>
            <dd>
              <StatusBadge status={settings.breakGlassEnabled ? "warning" : "neutral"}>
                {settings.breakGlassEnabled ? "Configured" : "Not configured"}
              </StatusBadge>
            </dd>
            <dt>External refresh bound</dt>
            <dd>
              {settings.refreshIntervalSeconds
                ? `${settings.refreshIntervalSeconds} seconds`
                : "Not applicable"}
            </dd>
            <dt>External maximum snapshot age</dt>
            <dd>
              {settings.maxSnapshotAgeSeconds
                ? `${settings.maxSnapshotAgeSeconds} seconds`
                : "Not applicable"}
            </dd>
            <dt>Your current authority</dt>
            <dd>
              <StatusBadge
                status={settings.localAuthority || settings.current ? "success" : "warning"}
              >
                {settings.localAuthority
                  ? "Current local authority"
                  : settings.current
                    ? "Current external observation"
                    : "Not current"}
              </StatusBadge>
            </dd>
            <dt>Your last identity check</dt>
            <dd>
              {settings.observedAt
                ? timestampDate(settings.observedAt).toLocaleString()
                : "No external observation"}
            </dd>
          </dl>
          <p className="text-sm text-muted-foreground">
            This status covers your account, not the whole directory. Stale or failed identity
            checks block access. SCIM does not refresh this check or grant group permissions.
          </p>
        </>
      ) : null}
    </section>
  );
}
