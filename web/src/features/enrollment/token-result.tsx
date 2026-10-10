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
import { downloadEnrollmentFile } from "./download";
import { enrollmentInstructionsQueryOptions } from "./queries";
import {
  enrollmentInstallScript,
  grantFormats,
  grantSnippet,
  provisioningFormats,
  provisioningSnippet,
  type GrantFormat,
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
  const [family, setFamily] = useState<GrantFormat>("apt");
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
        setCopyStatus("Clipboard access failed. Select the text and copy it manually.");
      }
    }
  }

  function downloadToken() {
    if (!active || !secret) return;
    try {
      downloadEnrollmentFile("provisioning-token", `${secret}\n`);
      setCopyFailed(false);
      setCopyStatus(
        "Token download requested. Protect and remove the downloaded copy after delivery.",
      );
    } catch {
      setCopyFailed(true);
      setCopyStatus(
        "The token file could not be downloaded. Copy the token and transfer it securely.",
      );
    }
  }

  if (!active) return null;
  const provisioning = credential.kind === "provisioning";
  const title = provisioning ? "Provisioning token" : "One-time enrollment code";
  const unavailable = credential.deliveryUnknown || !secret;
  const packageFamily = provisioning
    ? format === "kickstart"
      ? "dnf"
      : format === "autoinstall"
        ? "apt"
        : format === "cloud-init"
          ? family
          : null
    : family;
  const installScript = packageFamily
    ? enrollmentInstallScript(instructions.data, packageFamily)
    : "";
  const snippet =
    secret && instructions.isSuccess
      ? provisioning
        ? provisioningSnippet(format, secret, instructions.data, installScript)
        : grantSnippet(secret, instructions.data, installScript)
      : "";

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
              ? "The credential exists, but its secret is unavailable."
              : provisioning
                ? "A reusable, bounded token for automatic fleet enrollment. Shown only now."
                : "A single-use code to enroll one device now. Shown only now."}
          </DialogDescription>
        </DialogHeader>
        {unavailable ? (
          <div className="grid gap-2">
            <StatusBadge status="destructive" className="w-fit">
              {credential.deliveryUnknown ? "Secret delivery unknown" : "Secret unavailable"}
            </StatusBadge>
            <p className="text-sm">
              Revoke this {provisioning ? "token" : "code"} in the list, then create a replacement.
              Retrying cannot retrieve the secret. Do not assume issuance failed.
            </p>
          </div>
        ) : (
          <div className="grid gap-3">
            <p className="text-sm text-muted-foreground">
              Copy before closing. This dialog forgets the secret when dismissed or when your
              session ends. Clipboard and downloaded copies remain your responsibility.
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
            {!provisioning || format === "cloud-init" ? (
              <div className="grid gap-1.5">
                <Label htmlFor="enrollment-package-family">Package manager</Label>
                <SelectField
                  id="enrollment-package-family"
                  value={family}
                  options={grantFormats}
                  onValueChange={(value) => setFamily(value as GrantFormat)}
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
                  Reload installation instructions
                </Button>
              </div>
            ) : null}
            <p className="text-sm text-muted-foreground">
              {instructions.isPending
                ? "Loading this deployment's installation instructions."
                : instructions.isError
                  ? "Installation instructions are unavailable. Resolve the read failure before copying a snippet."
                  : installScript
                    ? "Includes installation from this deployment's configured signed repository."
                    : packageFamily
                      ? `No ${packageFamily.toUpperCase()} repository instructions are configured. Install the signed agent package and configuration before running this snippet.`
                      : "Install the verified agent package and configuration separately for this format."}{" "}
              Authenticate the deployment execution root and signed bootstrap bundle before
              enrollment. Public downloads alone do not establish root trust.
            </p>
            <Textarea
              data-sensitive="true"
              aria-label={
                provisioning ? `${format} provisioning snippet` : `${family} enrollment snippet`
              }
              readOnly
              spellCheck={false}
              autoComplete="off"
              className="min-h-64 font-mono text-xs"
              value={snippet}
            />
            <div className="flex flex-wrap gap-2">
              <Button
                variant="outline"
                disabled={!snippet}
                onClick={() =>
                  void copy(snippet, `${provisioning ? format : family.toUpperCase()} snippet`)
                }
              >
                Copy {provisioning ? format : family.toUpperCase()} snippet
              </Button>
              {provisioning && format === "nixos" ? (
                <Button variant="outline" onClick={downloadToken}>
                  Download sensitive token file
                </Button>
              ) : null}
            </div>
            {copyStatus ? (
              <p role={copyFailed ? "alert" : "status"} className="text-sm text-muted-foreground">
                {copyStatus}
              </p>
            ) : null}
          </div>
        )}
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
                  Keep credentials out of arguments, environment variables, URLs, logs, shell
                  history, golden images and the Nix store. The snippets put the credential in a
                  root-owned mode 0600 file. Base64 is not encryption. Protect copied snippets and
                  installer transport, caches and retained logs; remove delivered copies after use.
                </p>
                <p>
                  Install authenticated trust at /etc/lindm/execution-root.json and
                  /etc/lindm/bootstrap.dsse.json. Never replace trust or protected installation
                  state to retry enrollment.
                </p>
                {instructions.data?.executionRootUrl ? (
                  <a
                    className="underline"
                    href={instructions.data.executionRootUrl}
                    target="_blank"
                    rel="noreferrer"
                  >
                    Download execution root for independent authentication
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
                {instructions.data && !instructions.data.bootstrapBundleUrl ? (
                  <p>
                    Public bootstrap downloads are not configured. Obtain the trust files through
                    your deployment owner's authenticated installation channel.
                  </p>
                ) : null}
                <p>
                  Bootstrap may reserve a device without completing enrollment. Resume waits up to
                  one hour for any required independent approval and identity installation, then
                  fails visibly. After a timeout or transient failure, use the same protected
                  installation and run /usr/libexec/lindm/lindm-agent resume -wait-seconds 3600 as
                  root. Never generate another key to retry.
                </p>
                {provisioning ? (
                  <p>
                    Installer snippets are integration fragments, not complete OS profiles. Start
                    lindm-provision.service again after resolving a failed wait; its token file is
                    removed only after successful enrollment. NixOS uses a separately delivered,
                    target-encrypted systemd credential; follow the module comments. Browser
                    downloads do not enforce Unix ownership or permissions.
                  </p>
                ) : (
                  <p>
                    After a successful manual resume, remove /run/lindm-enrollment/grant from the
                    device.
                  </p>
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
