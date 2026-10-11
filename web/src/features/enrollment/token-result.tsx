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
        setCopyStatus("Couldn't copy. Select the text and copy it yourself.");
      }
    }
  }

  function downloadToken() {
    if (!active || !secret) return;
    try {
      downloadEnrollmentFile("provisioning-token", `${secret}\n`);
      setCopyFailed(false);
      setCopyStatus("Token file downloaded. Delete your copy once it's on the device.");
    } catch {
      setCopyFailed(true);
      setCopyStatus("Couldn't download the token file. Copy the token instead.");
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
                  Try again
                </Button>
              </div>
            ) : null}
            <p className="text-sm text-muted-foreground">
              {instructions.isPending
                ? "Loading install steps…"
                : instructions.isError
                  ? "Couldn't load install steps. Try again before copying."
                  : installScript
                    ? "Installs the lindm agent from your repository, then enrolls."
                    : packageFamily
                      ? `No ${packageFamily.toUpperCase()} repository is set up. Install the lindm agent first, then run this.`
                      : "Install the lindm agent separately for this format."}
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
                  Download token file
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
                  Keep the secret out of command lines, logs, URLs and images. Delete copies after
                  use.
                </p>
                <p>
                  The device needs /etc/lindm/execution-root.json and /etc/lindm/bootstrap.dsse.json
                  from you.
                </p>
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
                {instructions.data && !instructions.data.bootstrapBundleUrl ? (
                  <p>
                    Download links aren't set up. Get these files from whoever runs this deployment.
                  </p>
                ) : null}
                <p>
                  If enrollment times out, run /usr/libexec/lindm/lindm-agent resume -wait-seconds
                  3600 as root on the same device. Don't reinstall to retry.
                </p>
                {provisioning ? (
                  <p>
                    These snippets only add lindm to your installer. For NixOS, follow the comments
                    in the module.
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
