import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { RpcError } from "@/components/ui/rpc-error";
import { StatusBadge } from "@/components/ui/status-badge";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { enrollmentInstructionsQueryOptions } from "./queries";

export function RepositoryReadinessSection() {
  const lifetime = useAuthLifetime();
  const query = useQuery(enrollmentInstructionsQueryOptions(lifetime));
  const instructions = query.data;
  return (
    <section aria-labelledby="repository-readiness-heading" className="grid min-w-0 gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 id="repository-readiness-heading" className="text-base font-semibold">
          Agent repository
        </h2>
        <Button variant="outline" disabled={query.isFetching} onClick={() => void query.refetch()}>
          Check again
        </Button>
      </div>
      {query.isError ? <RpcError failure={toRpcFailure(query.error)} /> : null}
      {query.isPending ? (
        <p className="text-sm text-muted-foreground">Checking server configuration…</p>
      ) : null}
      {instructions ? (
        <>
          <div className="grid gap-2">
            <StatusBadge
              status={
                query.isError ? "warning" : instructions.readiness?.ready ? "success" : "warning"
              }
              className="w-fit"
            >
              {query.isError
                ? "Last check could not be refreshed"
                : instructions.readiness?.ready
                  ? "Ready for listed platforms"
                  : "Installation needs setup"}
            </StatusBadge>
            <p className="text-sm">
              {instructions.readiness?.ready
                ? "Agent packages are served only by this server. Availability below is not a claim of device health or platform qualification."
                : instructions.readiness?.remedy ||
                  "Configure releaseRepository and publish signed packages and deployment trust on this server."}
            </p>
            <p className="text-xs text-muted-foreground">
              Last successful check: {new Date(query.dataUpdatedAt).toLocaleString()}
            </p>
          </div>
          <ul className="divide-y border-y">
            {instructions.platforms.map((platform) => (
              <li
                key={platform.id}
                className="grid gap-2 py-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]"
              >
                <div className="grid content-start gap-1">
                  <span className="text-sm font-medium">{platform.label}</span>
                  <span className="text-xs text-muted-foreground">
                    {platform.architectures.length
                      ? platform.architectures.join(", ")
                      : "No package architecture available"}
                  </span>
                </div>
                <div className="grid gap-1">
                  <StatusBadge
                    status={platform.readiness?.ready ? "success" : "neutral"}
                    className="w-fit"
                  >
                    {platform.readiness?.ready ? "Install command available" : "Unavailable"}
                  </StatusBadge>
                  {!platform.readiness?.ready ? (
                    <p className="text-sm text-muted-foreground">
                      {platform.readiness?.remedy ||
                        "Package availability was not reported. Check server configuration."}
                    </p>
                  ) : null}
                </div>
              </li>
            ))}
          </ul>
          {!instructions.platforms.length ? (
            <p className="text-sm">
              No supported platform choices were returned. Check this server's release
              configuration.
            </p>
          ) : null}
          <details className="text-sm">
            <summary className="cursor-pointer">Repository and trust details</summary>
            <dl className="mt-3 grid gap-3 break-all text-muted-foreground">
              {[
                ["APT repository", instructions.aptRepository?.baseUrl || "Not published"],
                [
                  "APT signing key fingerprint",
                  instructions.aptRepository?.signingKeyFingerprint || "Not configured",
                ],
                ["RPM repository", instructions.dnfRepository?.baseUrl || "Not published"],
                [
                  "RPM signing key fingerprint",
                  instructions.dnfRepository?.signingKeyFingerprint || "Not configured",
                ],
                ["Arch repository", instructions.archRepository?.baseUrl || "Not published"],
                [
                  "Arch signing key fingerprint",
                  instructions.archRepository?.signingKeyFingerprint || "Not configured",
                ],
                ["Execution root SHA-256", instructions.executionRootSha256 || "Not available"],
                ["HTTPS trust", instructions.tlsCaSha256 || "System trust"],
                ["Readiness reason", instructions.readiness?.reason || "Not reported"],
              ].map(([label, value]) => (
                <div key={label}>
                  <dt className="font-medium">{label}</dt>
                  <dd className="select-text">{value}</dd>
                </div>
              ))}
            </dl>
          </details>
        </>
      ) : null}
    </section>
  );
}
