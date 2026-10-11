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
      <h2 className="text-lg font-semibold">Sign-in source</h2>
      <p>Set in the server configuration. You can't change it here.</p>
      {query.isPending ? <p role="status">Loading identity settings…</p> : null}
      {query.isError ? <RpcError failure={toRpcFailure(query.error)} /> : null}
      {settings && !query.isError ? (
        <>
          <dl className="grid gap-2 sm:grid-cols-2">
            <dt>Sign-in provider</dt>
            <dd>{settings.primarySource}</dd>
            <dt>Issuer</dt>
            <dd className="break-all">{settings.issuer}</dd>
            <dt>Upstream provider</dt>
            <dd>{settings.brokerEnabled ? settings.upstreamSource : "Not configured"}</dd>
            <dt>SCIM provisioning</dt>
            <dd>
              <StatusBadge status={settings.scimEnabled ? "info" : "neutral"}>
                {settings.scimEnabled ? "On (removes access only)" : "Not configured"}
              </StatusBadge>
            </dd>
            <dt>Local emergency sign-in</dt>
            <dd>
              <StatusBadge status={settings.breakGlassEnabled ? "warning" : "neutral"}>
                {settings.breakGlassEnabled ? "Configured" : "Not configured"}
              </StatusBadge>
            </dd>
            <dt>Access recheck interval</dt>
            <dd>
              {settings.refreshIntervalSeconds
                ? `${settings.refreshIntervalSeconds} seconds`
                : "Not applicable"}
            </dd>
            <dt>Maximum time between rechecks</dt>
            <dd>
              {settings.maxSnapshotAgeSeconds
                ? `${settings.maxSnapshotAgeSeconds} seconds`
                : "Not applicable"}
            </dd>
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
            <dt>Last checked</dt>
            <dd>
              {settings.observedAt
                ? timestampDate(settings.observedAt).toLocaleString()
                : "Not checked yet"}
            </dd>
          </dl>
          <p className="text-sm text-muted-foreground">
            This is about your own account. If the check fails or is too old, you lose access until
            it succeeds.
          </p>
        </>
      ) : null}
    </section>
  );
}
