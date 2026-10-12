import type { Timestamp } from "@bufbuild/protobuf/wkt";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
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
import { toRpcFailure } from "@/lib/errors";
import { formatTimestamp } from "@/lib/time";
import { enrollmentInstructionsQueryOptions } from "./queries";
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

function SecretDialog({ credential, onDismiss }: SecretDialogProps) {
  const lifetime = useAuthLifetime();
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
  const unavailable = credential.deliveryUnknown || !secret;
  const allPlatforms = instructions.data?.platforms ?? [];
  // The registry decides which releases support an installer format.
  const platforms = provisioning
    ? allPlatforms.filter((item) => item.provisioningFormats.includes(format))
    : allPlatforms;
  const platform = platforms.find((item) => item.id === platformId) ?? platforms[0];
  const installScript = enrollmentInstallScript(instructions.data, platform);
  const readiness = !instructions.data?.readiness?.ready
    ? instructions.data?.readiness
    : platform?.readiness;
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
      <DialogContent className="max-h-[90dvh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>
            {unavailable
              ? "This was created, but the secret can't be shown."
              : provisioning
                ? "Reusable token for automatic enrollment. Copy it now; it won't be shown again."
                : "Single-use code to enroll one device. Copy it now; it won't be shown again."}
          </DialogDescription>
        </DialogHeader>
        {unavailable ? (
          <div className="grid gap-2">
            <StatusBadge status="destructive" className="w-fit">
              {credential.deliveryUnknown ? "Secret not shown" : "Secret unavailable"}
            </StatusBadge>
            <p className="text-sm">
              Revoke this {provisioning ? "token" : "code"} in the list, then create a new one.
            </p>
          </div>
        ) : (
          <div className="grid gap-3">
            <p className="text-sm text-muted-foreground">
              Copy it before closing. It's forgotten when you close this dialog.
            </p>
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
            <p className="text-sm text-muted-foreground">
              {instructions.isPending
                ? "Loading install command…"
                : instructions.isError
                  ? "Couldn't load install instructions. Try again before copying."
                  : snippet
                    ? provisioning
                      ? "Installs the signed agent from this server and enrolls this device on its first boot."
                      : "Installs the signed agent from this server, then enrolls this device."
                    : !platform
                      ? "No supported operating system uses this installer format."
                      : readiness?.remedy ||
                        "Ask your server administrator to configure releaseRepository and publish signed packages and deployment trust."}
            </p>
            {!snippet && instructions.isSuccess ? (
              <StatusBadge status="warning" className="w-fit">
                Install command unavailable
              </StatusBadge>
            ) : null}
            <p className="text-sm">
              {provisioning
                ? "This installer input contains a reusable secret. Keep it out of images and logs."
                : "Run on the intended device with sudo access and shell history disabled. This command contains a single-use secret."}
            </p>
            <Textarea
              data-sensitive="true"
              aria-label={
                provisioning ? `${format} provisioning snippet` : "Install and enroll command"
              }
              readOnly
              spellCheck={false}
              autoComplete="off"
              className="field-sizing-fixed h-48 min-h-48 font-mono text-xs"
              value={snippet}
            />
            <div className="flex flex-wrap gap-2">
              <Button
                variant="default"
                disabled={!snippet}
                onClick={() =>
                  void copy(snippet, provisioning ? `${format} snippet` : "Install command")
                }
              >
                Copy {provisioning ? `${format} snippet` : "install command"}
              </Button>
            </div>
            {copyStatus ? (
              <p role={copyFailed ? "alert" : "status"} className="text-sm text-muted-foreground">
                {copyStatus}
              </p>
            ) : null}
          </div>
        )}
        {!unavailable && !(provisioning && format === "nixos") ? (
          <details className="text-sm">
            <summary className="cursor-pointer">What this does</summary>
            <ol className="mt-2 list-decimal space-y-2 pl-5 text-muted-foreground">
              <li>Checks the selected operating system and available package architecture.</li>
              <li>
                {installsInInstaller
                  ? "Inside the installer, before the first boot: installs package tools from the device's distribution sources."
                  : "Installs package tools from the device's existing distribution sources."}
                {instructions.data?.tlsCaPem
                  ? " Verifies the supplied private HTTPS CA fingerprint, then adds it to system trust."
                  : " Uses the device's system HTTPS trust."}
              </li>
              <li>
                Authenticates the package signing key, adds only this server's signed agent
                repository, and installs lindm-agent.
              </li>
              <li>
                Verifies the execution root fingerprint and downloads the signed bootstrap bundle.
              </li>
              <li>
                Starts the agent and enrolls with this{" "}
                {provisioning ? "token on first boot" : "code"}. Approval may be required; waiting
                stops after one hour without claiming enrollment.
              </li>
            </ol>
          </details>
        ) : null}
        <details className="text-sm">
          <summary className="cursor-pointer">Credential details and safe delivery</summary>
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
                  Keep the secret out of command lines, logs, URLs and images. Delete copies after
                  use.
                </p>
                {!(provisioning && format === "nixos") ? (
                  <p>
                    The command pins the HTTPS CA when needed, the package signer and the execution
                    root. Downloading a file alone does not authenticate it.
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
                {readiness?.reason ? (
                  <p className="break-all">Readiness: {readiness.reason}</p>
                ) : null}
                <p>
                  If enrollment times out, run /usr/libexec/lindm/lindm-agent resume -wait-seconds
                  3600 as root on the same device. Don't reinstall to retry.
                </p>
                {provisioning ? (
                  <p>
                    Merge the snippet into your complete installer configuration; it doesn't replace
                    it. Delete installer and seed copies after enrollment.
                  </p>
                ) : (
                  <p>When enrollment finishes, delete /run/lindm-enrollment/grant on the device.</p>
                )}
              </>
            ) : null}
          </div>
        </details>
        <DialogFooter>
          <Button variant="outline" onClick={dismiss}>
            {unavailable ? "Close" : "Done, forget secret"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
