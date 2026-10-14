// SPDX-License-Identifier: Apache-2.0

import type { Timestamp } from "@bufbuild/protobuf/wkt";
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import type { EnrollmentPlatform } from "../../../gen/lindm/admin/v1/enrollment_instructions_pb";
import type { FleetOSCount } from "../../../gen/lindm/admin/v1/fleet_summary_pb";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RpcError } from "@/components/ui/rpc-error";
import { SelectField } from "@/components/ui/select-field";
import { StatusBadge } from "@/components/ui/status-badge";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { toRpcFailure } from "@/lib/errors";
import { canPermission } from "@/lib/permissions";
import { formatTimestamp } from "@/lib/time";
import { enrollmentInstructionsQueryOptions, fleetOperatingSystemsQueryOptions } from "./queries";
import {
  enrollmentInstallScript,
  grantSnippet,
  provisioningFormats,
  provisioningSnippet,
  type ProvisioningFormat,
} from "./snippets";

type CredentialDetails = {
  id: string;
  secret: string | null;
  expiresAt?: Timestamp;
  deliveryUnknown: boolean;
};

export type EnrollmentCredential =
  ({ kind: "grant" } & CredentialDetails) | ({ kind: "provisioning" } & CredentialDetails);

type SecretDialogProps = {
  credential: EnrollmentCredential;
  onDismiss: () => void;
};

export function EnrollmentSecretDialog(props: SecretDialogProps) {
  return <SecretDialog key={`${props.credential.kind}:${props.credential.id}`} {...props} />;
}

// Whether devices reporting this OS ID and VERSION_ID fit the platform's
// registry version rule. The fleet summary carries no VARIANT_ID.
function platformMatches(platform: EnrollmentPlatform, group: FleetOSCount): boolean {
  if (platform.osId !== group.osId) return false;
  const version = group.osVersion;
  switch (platform.versionRule) {
    case "exact":
      return platform.versionIds.includes(version);
    case "major":
      return platform.versionIds.some(
        (major) => version === major || version.startsWith(`${major}.`),
      );
    case "absent":
      return version === "";
    case "snapshot":
      return /^\d{8}$/.test(version);
    case "any":
      return true;
    default:
      return false;
  }
}

// The most common OS among authorized devices that one of these platforms covers.
function fleetDefaultPlatform(platforms: EnrollmentPlatform[], groups: FleetOSCount[]) {
  for (const group of groups) {
    if (!group.osId) continue;
    const match = platforms.find((platform) => platformMatches(platform, group));
    if (match) return match;
  }
  return undefined;
}

// One sentence naming what blocks the install command and where to act on it.
// A platform's readiness carries the server-wide reason when that comes first.
function UnavailableInstall({ platform }: { platform: EnrollmentPlatform }) {
  const reason = platform.readiness?.reason ?? "";
  if (reason === "platform_installation_gated") {
    return (
      <p className="text-sm">
        lindm can't install the agent on {platform.label} yet. Choose another operating system.
      </p>
    );
  }
  const settings = (
    <Link
      to="/settings"
      hash="agent-repository"
      target="_blank"
      rel="noreferrer"
      className="underline underline-offset-4"
    >
      Settings › Agent repository
      <span className="sr-only"> (opens in a new tab)</span>
    </Link>
  );
  return (
    <p className="text-sm">
      {reason.startsWith("native_")
        ? `The agent repository for ${platform.label} is not ready. Open `
        : "Agent installation is not ready on this server. Open "}
      {settings}.
    </p>
  );
}

function SecretDialog({ credential, onDismiss }: SecretDialogProps) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const [generation] = useState(lifetime.generation);
  const [secret, setSecret] = useState(credential.deliveryUnknown ? null : credential.secret);
  const [open, setOpen] = useState(true);
  const [format, setFormat] = useState<ProvisioningFormat>("cloud-init");
  const [platformId, setPlatformId] = useState("");
  const [copyStatus, setCopyStatus] = useState("");
  const [copyFailed, setCopyFailed] = useState(false);
  const mounted = useRef(true);
  const active = open && generation === lifetime.generation && !lifetime.signal.aborted;
  const instructions = useQuery({
    ...enrollmentInstructionsQueryOptions(lifetime),
    enabled: active && !!secret,
  });
  const fleet = useQuery({
    ...fleetOperatingSystemsQueryOptions(lifetime),
    enabled: active && !!secret && canPermission(principal, "fleet.read"),
  });

  useEffect(() => {
    mounted.current = true;
    function clear() {
      setSecret(null);
      setCopyStatus("");
      setOpen(false);
      onDismiss();
    }
    lifetime.signal.addEventListener("abort", clear, { once: true });
    return () => {
      mounted.current = false;
      lifetime.signal.removeEventListener("abort", clear);
    };
  }, [lifetime, onDismiss]);

  function dismiss() {
    setSecret(null);
    setCopyStatus("");
    setOpen(false);
    onDismiss();
  }

  async function copy(value: string, label: string) {
    if (!active) return;
    try {
      await navigator.clipboard.writeText(value);
      if (mounted.current && !lifetime.signal.aborted) {
        setCopyFailed(false);
        setCopyStatus(`${label} copied. Clear the clipboard after delivery.`);
      }
    } catch {
      if (mounted.current && !lifetime.signal.aborted) {
        setCopyFailed(true);
        setCopyStatus("Couldn't copy. Select the text and copy it yourself.");
      }
    }
  }

  if (!active) return null;
  const provisioning = credential.kind === "provisioning";
  const title = provisioning ? "Provisioning token" : "One-time enrollment code";
  const formatLabel =
    provisioningFormats.find((item) => item.value === format)?.label ?? "installer";
  const unavailable = credential.deliveryUnknown || !secret;
  const allPlatforms = instructions.data?.platforms ?? [];
  // The registry decides which releases support an installer format.
  const platforms = provisioning
    ? allPlatforms.filter((item) => item.provisioningFormats.includes(format))
    : allPlatforms;
  // Preselect the fleet's most common covered OS; otherwise the admin chooses.
  const platform =
    platforms.find((item) => item.id === platformId) ??
    fleetDefaultPlatform(platforms, fleet.data ?? []);
  const installScript = enrollmentInstallScript(instructions.data, platform);
  const snippet =
    secret && instructions.isSuccess
      ? provisioning
        ? provisioningSnippet(format, secret, instructions.data, installScript)
        : grantSnippet(secret, instructions.data, installScript)
      : "";
  // Kickstart and AutoYaST install inside the installer; the others on first boot.
  const installsInInstaller = provisioning && (format === "kickstart" || format === "autoyast");

  return (
    <Dialog
      open
      onOpenChange={(next) => {
        if (!next) dismiss();
      }}
    >
      <DialogContent className="flex max-h-[90dvh] flex-col gap-0 overflow-hidden p-0 sm:max-w-2xl">
        <DialogHeader className="p-4 pr-12">
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>
            {unavailable
              ? "The server created the credential. The console cannot show its secret."
              : provisioning
                ? "Reusable token for automatic enrollment. Copy it now. The console shows it only once."
                : "Single-use code to enroll one device. Copy it now. The console shows it only once."}
          </DialogDescription>
          <p className="text-sm">Expires: {formatTimestamp(credential.expiresAt).local}</p>
        </DialogHeader>
        <div className="grid min-h-0 gap-4 overflow-y-auto px-4 pb-4">
          {unavailable ? (
            <div className="grid gap-2">
              <StatusBadge status="destructive" className="w-fit">
                {credential.deliveryUnknown ? "Secret not shown" : "Secret unavailable"}
              </StatusBadge>
              <p className="text-sm">
                Revoke this {provisioning ? "token" : "code"} in the list. Create a new one.
              </p>
            </div>
          ) : (
            <div className="grid gap-3">
              <Label htmlFor="enrollment-secret">{title}</Label>
              <div className="flex flex-wrap gap-2">
                <Input
                  id="enrollment-secret"
                  data-sensitive="true"
                  className="min-w-0 flex-1 font-mono"
                  readOnly
                  value={secret ?? ""}
                  autoComplete="off"
                  spellCheck={false}
                />
                <Button variant="outline" onClick={() => void copy(secret ?? "", title)}>
                  Copy {provisioning ? "token" : "code"}
                </Button>
              </div>
              {provisioning ? (
                <div className="grid gap-1.5">
                  <Label htmlFor="provisioning-format">Installer format</Label>
                  <SelectField
                    id="provisioning-format"
                    value={format}
                    options={provisioningFormats}
                    onValueChange={(value) => setFormat(value as ProvisioningFormat)}
                  />
                </div>
              ) : null}
              {platforms.length ? (
                <div className="grid gap-1.5">
                  <Label htmlFor="enrollment-platform">Operating system</Label>
                  <SelectField
                    id="enrollment-platform"
                    value={platform?.id ?? ""}
                    placeholder="Choose an OS"
                    options={platforms.map((item) => ({ value: item.id, label: item.label }))}
                    onValueChange={setPlatformId}
                  />
                </div>
              ) : null}
              {instructions.isError ? (
                <div className="grid gap-2">
                  <RpcError failure={toRpcFailure(instructions.error)} />
                  <Button
                    variant="outline"
                    className="w-fit"
                    disabled={instructions.isFetching}
                    onClick={() => void instructions.refetch()}
                  >
                    Try again
                  </Button>
                </div>
              ) : null}
              {instructions.isPending ? (
                <p className="text-sm text-muted-foreground">Loading install command…</p>
              ) : instructions.isError ? (
                <p className="text-sm text-muted-foreground">
                  Couldn't load install instructions. Try again before copying.
                </p>
              ) : snippet ? (
                <>
                  <p className="text-sm text-muted-foreground">
                    {provisioning
                      ? installsInInstaller
                        ? "The installer installs the signed agent. The device enrolls on its first boot."
                        : "On its first boot, the device installs the signed agent and enrolls."
                      : "The command installs the signed agent from this server and starts enrollment."}
                  </p>
                  <p className="text-sm">
                    {provisioning
                      ? "This installer input contains a reusable secret. Keep it out of images and logs."
                      : "Run on the intended device with sudo access and shell history disabled. This command contains a single-use secret."}
                  </p>
                  {provisioning ? (
                    <p className="text-sm">
                      Merge this snippet into your complete installer configuration. It does not
                      replace that configuration.
                    </p>
                  ) : null}
                  <div className="flex flex-wrap gap-2">
                    <Button
                      variant="default"
                      onClick={() =>
                        void copy(
                          snippet,
                          provisioning ? `${formatLabel} snippet` : "Install command",
                        )
                      }
                    >
                      Copy {provisioning ? `${formatLabel} snippet` : "install command"}
                    </Button>
                  </div>
                  <Textarea
                    data-sensitive="true"
                    aria-label={
                      provisioning
                        ? `${formatLabel} provisioning snippet`
                        : "Install and enroll command"
                    }
                    readOnly
                    spellCheck={false}
                    autoComplete="off"
                    className="field-sizing-fixed h-48 min-h-48 font-mono text-xs"
                    value={snippet}
                  />
                  <p className="text-sm text-muted-foreground">
                    After you run it, close this dialog. Refresh Enrollment. Review the device in
                    Enrollment if it needs approval. Copying a command does not confirm enrollment.
                  </p>
                </>
              ) : !platforms.length ? (
                <p className="text-sm">No supported operating system uses this installer format.</p>
              ) : platform ? (
                <UnavailableInstall platform={platform} />
              ) : null}

              {copyStatus ? (
                <p role={copyFailed ? "alert" : "status"} className="text-sm text-muted-foreground">
                  {copyStatus}
                </p>
              ) : null}
            </div>
          )}
          <details className="text-sm">
            <summary className="cursor-pointer">Details</summary>
            {snippet && !(provisioning && format === "nixos") ? (
              <ol className="mt-2 list-decimal space-y-2 pl-5 text-muted-foreground">
                <li>Checks the selected operating system and available package architecture.</li>
                <li>
                  {installsInInstaller
                    ? "Inside the installer, before the first boot: installs package tools from the device's distribution sources."
                    : "Installs package tools from the device's existing distribution sources."}
                  {instructions.data?.tlsCaPem
                    ? " The command verifies the private HTTPS CA fingerprint. It adds the CA to system trust."
                    : " Uses the device's system HTTPS trust."}
                </li>
                <li>
                  The command authenticates the package signing key. It adds only this server&apos;s
                  signed agent repository. It installs lindm-agent.
                </li>
                <li>
                  The command verifies the execution root fingerprint. It downloads the signed
                  bootstrap bundle.
                </li>
                <li>
                  The agent enrolls with this {provisioning ? "token on first boot" : "code"}. The
                  enrollment policy determines whether enrollment needs approval. The command stops
                  waiting after one hour. This timeout does not confirm enrollment.
                </li>
              </ol>
            ) : null}
            <div className="mt-2 grid gap-2 text-muted-foreground">
              <dl className="grid gap-1 break-all">
                <div>
                  <dt className="inline font-medium">{provisioning ? "Token" : "Grant"} ID: </dt>
                  <dd className="inline">{credential.id}</dd>
                </div>
                <div>
                  <dt className="inline font-medium">Expires: </dt>
                  <dd className="inline">{formatTimestamp(credential.expiresAt).local}</dd>
                </div>
              </dl>
              {!unavailable ? (
                <>
                  <p>
                    Keep the secret out of command lines, logs, URLs and images. Remove copies after
                    use.
                  </p>
                  {!(provisioning && format === "nixos") ? (
                    <p>
                      The command pins the HTTPS CA when needed, the package signer and the
                      execution root. Downloading a file alone does not authenticate it.
                    </p>
                  ) : null}
                  {instructions.data?.executionRootUrl ? (
                    <a
                      className="underline"
                      href={instructions.data.executionRootUrl}
                      target="_blank"
                      rel="noreferrer"
                    >
                      Download execution root
                    </a>
                  ) : null}
                  {instructions.data?.bootstrapBundleUrl ? (
                    <a
                      className="underline"
                      href={instructions.data.bootstrapBundleUrl}
                      target="_blank"
                      rel="noreferrer"
                    >
                      Download signed bootstrap bundle
                    </a>
                  ) : null}
                  {instructions.data?.executionRootSha256 ? (
                    <p className="break-all">
                      Execution root SHA-256: {instructions.data.executionRootSha256}
                    </p>
                  ) : null}
                  <p>
                    If enrollment times out, run /usr/libexec/lindm/lindm-agent resume -wait-seconds
                    3600 as root on the same device. Don't reinstall to retry.
                  </p>
                  {provisioning ? (
                    <p>Remove installer and seed copies after enrollment.</p>
                  ) : (
                    <p>
                      When enrollment finishes, remove /run/lindm-enrollment/grant from the device.
                    </p>
                  )}
                </>
              ) : null}
            </div>
          </details>
        </div>
        <DialogFooter className="border-t p-4">
          <Button variant="outline" onClick={dismiss}>
            {unavailable ? "Close" : "Done, forget secret"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
