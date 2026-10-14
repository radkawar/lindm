// SPDX-License-Identifier: Apache-2.0

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

// The server release carries the repository; settings only shows verified state.
const SERVER_SETUP_GUIDE =
  "/help/security-and-operations.md#prepare-the-servers-installation-repository";

// Server-wide readiness reasons in admin terms. The server's exact remedy,
// which names configuration keys, stays in technical details.
const SERVER_CAUSE: Record<string, string> = {
  native_repository_unavailable: "This server cannot verify its signed agent repository.",
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
  if (readiness?.ready) return "Devices install signed agent packages from this server.";
  return (
    SERVER_CAUSE[readiness?.reason ?? ""] ??
    "This server cannot provide agent packages. Open the trust details for its reported cause."
  );
}

// Only what differs from the server-wide state above; nothing when the row
// shares the server's reason.
function rowNote(platform: EnrollmentPlatform, server: EnrollmentReadiness | undefined) {
  // The "Not supported yet" group already says why; its rows add nothing.
  if (platform.support !== EnrollmentPlatformSupport.SUPPORTED) return "";
  const missing = platform.unpublishedArchitectures;
  if (platform.readiness?.ready)
    return missing.length ? `No agent package for ${missing.join(", ")}` : "";
  const reason = platform.readiness?.reason ?? "";
  if (!server?.ready && reason === server?.reason && platform.readiness?.remedy === server?.remedy)
    return "";
  switch (reason) {
    case "native_repository_unavailable": {
      const kind = PACKAGE_KIND[platform.packageFamily];
      return kind
        ? `${kind} repository check failed. Open trust details.`
        : "Repository check failed. Open trust details.";
    }
    case "native_architecture_unavailable":
      return missing.length
        ? `No agent package for ${missing.join(", ")}`
        : "This release has no agent package for these architectures.";
    default:
      return "Installation unavailable. Open trust details for the reported cause.";
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
    <ul className="grid grid-cols-1 gap-x-6 border-t pt-2 sm:grid-cols-2 lg:grid-cols-3">
      {platforms.map((platform) => {
        const versions = platform.agentPackages.map(
          (agentPackage) => `${agentPackage.architecture}: ${agentPackage.version}`,
        );
        const detail = [
          versions.length ? versions.join(", ") : platform.architectures.join(", "),
          rowNote(platform, server),
        ]
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
        <p className="text-sm text-muted-foreground">Checking agent packages…</p>
      ) : null}
      {instructions ? (
        <>
          <div className="grid gap-2">
            <StatusBadge
              status={query.isError ? "warning" : server?.ready ? "success" : "warning"}
              className="w-fit"
            >
              {query.isError
                ? "Could not refresh the last check"
                : server?.ready
                  ? "Ready"
                  : "Repository needs attention"}
            </StatusBadge>
            <p className="max-w-prose text-sm">
              {setupSentence(server)}{" "}
              <a className="font-medium underline underline-offset-4" href={SERVER_SETUP_GUIDE}>
                Installation guide
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
                <h3 className="text-sm font-semibold">Needs attention ({needsSetup.length})</h3>
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
                    lindm does not support agent installation on these releases.
                  </p>
                  <PlatformRows
                    platforms={unsupported}
                    server={server}
                    empty="lindm supports every listed platform."
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
                value: instructions.aptRepository?.signingKeyFingerprint || "Not available",
              },
              {
                label: "RPM repository",
                value: instructions.dnfRepository?.baseUrl || "Not published",
              },
              {
                label: "RPM signing key fingerprint",
                value: instructions.dnfRepository?.signingKeyFingerprint || "Not available",
              },
              {
                label: "Arch repository",
                value: instructions.archRepository?.baseUrl || "Not published",
              },
              {
                label: "Arch signing key fingerprint",
                value: instructions.archRepository?.signingKeyFingerprint || "Not available",
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
    if (
      !readiness ||
      readiness.ready ||
      (readiness.reason === server?.reason && readiness.remedy === server?.remedy)
    )
      continue;
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
