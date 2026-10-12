import { timestampFromMs } from "@bufbuild/protobuf/wkt";
import { useQuery } from "@tanstack/react-query";
import {
  EnrollmentPlatformSupport,
  type EnrollmentPlatform,
  type EnrollmentReadiness,
} from "../../../gen/lindm/admin/v1/enrollment_instructions_pb";
import { Timestamp } from "@/components/ui/timestamp";
import { RpcError } from "@/components/ui/rpc-error";
import { StatusBadge } from "@/components/ui/status-badge";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { enrollmentInstructionsQueryOptions } from "./queries";

// Server setup for agent installation (publishing signed packages, signer
// fingerprints, restart) is documented once; the console links it instead of
// repeating server configuration keys.
const SERVER_SETUP_GUIDE =
  "https://github.com/radkawar/lindm/blob/main/docs/security-and-operations.md#prepare-the-servers-installation-repository";

// Server-wide readiness reasons in admin terms. The server's exact remedy,
// which names configuration keys, stays in technical details.
const SERVER_CAUSE: Record<string, string> = {
  native_repository_unavailable: "No signed agent packages are published on this server yet.",
  execution_bootstrap_missing:
    "This server has no signed bootstrap trust yet, so new devices cannot verify their enrollment.",
  device_origin_missing: "This server has no public address for devices yet.",
  https_trust_unavailable: "New devices cannot verify this server's HTTPS certificate yet.",
};

const PACKAGE_KIND: Record<string, string> = {
  apt: "DEB",
  dnf: "RPM",
  zypper: "RPM",
  pacman: "Arch",
};

function setupSentence(readiness: EnrollmentReadiness | undefined) {
  const action =
    "To make a platform installable, publish signed agent packages for its package format and architectures on this server, then restart it.";
  if (readiness?.ready)
    return `Devices install the agent only from packages this server publishes. ${action}`;
  const cause =
    SERVER_CAUSE[readiness?.reason ?? ""] ??
    "This server is not ready to install the agent; its exact message is in the details below.";
  return `${cause} ${action}`;
}

// Only what differs from the server-wide state above; nothing when the row
// shares the server's reason.
function rowNote(platform: EnrollmentPlatform, server: EnrollmentReadiness | undefined) {
  // The "Not supported yet" group already says why; its rows add nothing.
  if (platform.support !== EnrollmentPlatformSupport.SUPPORTED) return "";
  const missing = platform.unpublishedArchitectures;
  if (platform.readiness?.ready)
    return missing.length ? `No packages published for ${missing.join(", ")}` : "";
  const reason = platform.readiness?.reason ?? "";
  if (!server?.ready && reason === server?.reason) return "";
  switch (reason) {
    case "native_repository_unavailable": {
      const kind = PACKAGE_KIND[platform.packageFamily];
      return kind ? `No signed ${kind} packages published` : "No signed packages published";
    }
    case "native_architecture_unavailable":
      return missing.length
        ? `No packages published for ${missing.join(", ")}`
        : "No packages published for its architectures";
    default:
      return "Not installable; the server's reason is in the details below";
  }
}

function PlatformRows({
  platforms,
  server,
  empty,
}: {
  platforms: EnrollmentPlatform[];
  server: EnrollmentReadiness | undefined;
  empty: string;
}) {
  if (!platforms.length) return <p className="text-sm text-muted-foreground">{empty}</p>;
  return (
    <ul className="grid grid-cols-2 gap-x-6 border-t pt-2 lg:grid-cols-3">
      {platforms.map((platform) => {
        const detail = [platform.architectures.join(", "), rowNote(platform, server)]
          .filter(Boolean)
          .join(" · ");
        return (
          <li key={platform.id} className="grid content-start py-1">
            <span className="text-sm">{platform.label}</span>
            {detail ? <span className="text-xs text-muted-foreground">{detail}</span> : null}
          </li>
        );
      })}
    </ul>
  );
}

export function RepositoryReadinessSection() {
  const lifetime = useAuthLifetime();
  const query = useQuery(enrollmentInstructionsQueryOptions(lifetime));
  const instructions = query.data;
  const server = instructions?.readiness;
  const platforms = instructions?.platforms ?? [];
  const supported = platforms.filter(
    (platform) => platform.support === EnrollmentPlatformSupport.SUPPORTED,
  );
  const ready = supported.filter((platform) => platform.readiness?.ready);
  const needsSetup = supported.filter((platform) => !platform.readiness?.ready);
  const unsupported = platforms.filter(
    (platform) => platform.support !== EnrollmentPlatformSupport.SUPPORTED,
  );
  return (
    <section
      id="agent-repository"
      aria-labelledby="repository-readiness-heading"
      className="grid min-w-0 scroll-mt-20 gap-4"
    >
      <h2 id="repository-readiness-heading" className="text-base font-semibold">
        Agent repository
      </h2>
      {query.isError ? <RpcError failure={toRpcFailure(query.error)} /> : null}
      {query.isPending ? (
        <p className="text-sm text-muted-foreground">Checking server configuration…</p>
      ) : null}
      {instructions ? (
        <>
          <div className="grid gap-2">
            <StatusBadge
              status={query.isError ? "warning" : server?.ready ? "success" : "warning"}
              className="w-fit"
            >
              {query.isError
                ? "Last check could not be refreshed"
                : server?.ready
                  ? "Ready for listed platforms"
                  : "Installation needs setup"}
            </StatusBadge>
            <p className="max-w-prose text-sm">
              {setupSentence(server)}{" "}
              <a
                className="font-medium underline underline-offset-4"
                href={SERVER_SETUP_GUIDE}
                target="_blank"
                rel="noreferrer"
              >
                Server setup guide
              </a>
            </p>
            <p className="text-xs text-muted-foreground">
              Last successful check: <Timestamp value={timestampFromMs(query.dataUpdatedAt)} />
            </p>
          </div>
          {platforms.length ? (
            <>
              <div className="grid gap-2">
                <h3 className="text-sm font-semibold">Ready ({ready.length})</h3>
                <PlatformRows
                  platforms={ready}
                  server={server}
                  empty="No platform is installable from this server yet."
                />
              </div>
              <div className="grid gap-2">
                <h3 className="text-sm font-semibold">
                  Supported, needs setup ({needsSetup.length})
                </h3>
                <PlatformRows
                  platforms={needsSetup}
                  server={server}
                  empty="Every supported platform is installable."
                />
              </div>
              <details>
                <summary className="w-fit cursor-pointer text-sm font-semibold">
                  Not supported yet ({unsupported.length})
                </summary>
                <div className="mt-2 grid gap-2">
                  <p className="text-sm text-muted-foreground">
                    lindm cannot install its agent on these releases yet, whatever this server
                    publishes.
                  </p>
                  <PlatformRows
                    platforms={unsupported}
                    server={server}
                    empty="Every listed platform is supported."
                  />
                </div>
              </details>
            </>
          ) : (
            <p className="text-sm">
              The server returned no platforms. Check that this server's release matches this
              console.
            </p>
          )}
          <TechnicalDetails
            summary="Repository and trust details"
            className="text-sm"
            items={[
              {
                label: "APT repository",
                value: instructions.aptRepository?.baseUrl || "Not published",
              },
              {
                label: "APT signing key fingerprint",
                value: instructions.aptRepository?.signingKeyFingerprint || "Not configured",
              },
              {
                label: "RPM repository",
                value: instructions.dnfRepository?.baseUrl || "Not published",
              },
              {
                label: "RPM signing key fingerprint",
                value: instructions.dnfRepository?.signingKeyFingerprint || "Not configured",
              },
              {
                label: "Arch repository",
                value: instructions.archRepository?.baseUrl || "Not published",
              },
              {
                label: "Arch signing key fingerprint",
                value: instructions.archRepository?.signingKeyFingerprint || "Not configured",
              },
              {
                label: "Execution root SHA-256",
                value: instructions.executionRootSha256 || "Not available",
              },
              { label: "HTTPS trust", value: instructions.tlsCaSha256 || "System trust" },
              { label: "Readiness reason", value: server?.reason || "Not reported" },
              { label: "Server message", value: server?.remedy },
            ]}
          >
            <PlatformReasons platforms={platforms} server={server} />
          </TechnicalDetails>
        </>
      ) : null}
    </section>
  );
}

// Exact per-platform server messages that differ from the server-wide one,
// each listed once with the platforms it applies to.
function PlatformReasons({
  platforms,
  server,
}: {
  platforms: EnrollmentPlatform[];
  server: EnrollmentReadiness | undefined;
}) {
  const byRemedy = new Map<string, string[]>();
  for (const platform of platforms) {
    const readiness = platform.readiness;
    if (!readiness || readiness.ready || readiness.reason === (server?.reason ?? "")) continue;
    byRemedy.set(readiness.remedy, [...(byRemedy.get(readiness.remedy) ?? []), platform.label]);
  }
  if (!byRemedy.size) return null;
  return (
    <dl className="mt-2 grid gap-1 break-all">
      {[...byRemedy].map(([remedy, labels]) => (
        <div key={remedy}>
          <dt className="inline font-medium">{labels.join(", ")}: </dt>
          <dd className="inline font-mono">{remedy}</dd>
        </div>
      ))}
    </dl>
  );
}
