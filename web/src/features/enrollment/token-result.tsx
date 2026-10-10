import { useState } from "react";
import type { CreateProvisioningTokenResponse } from "../../../gen/lindm/admin/v1/provisioning_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import { Textarea } from "@/components/ui/textarea";
import { formatTimestamp } from "@/lib/time";
import { provisioningFormats, provisioningSnippet, type ProvisioningFormat } from "./snippets";
import { downloadEnrollmentFile } from "./download";

export function ProvisioningTokenResult({
  result,
  onDismiss,
}: {
  result: CreateProvisioningTokenResponse;
  onDismiss: () => void;
}) {
  const [format, setFormat] = useState<ProvisioningFormat>("cloud-init");
  const unavailable = result.secretDeliveryUnknown || !result.secret;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Provisioning credential issued</CardTitle>
      </CardHeader>
      <CardContent className="grid gap-4">
        <p className="break-all text-sm">
          Token {result.tokenId} · Expires {formatTimestamp(result.expiresAt).local}
        </p>
        {unavailable ? (
          <Alert variant="destructive">
            <AlertTitle>Secret delivery unknown — not recoverable</AlertTitle>
            <AlertDescription>
              A retry cannot retrieve the secret. Revoke this token below, then issue a replacement
              with a new request ID. Do not assume the original request failed.
            </AlertDescription>
          </Alert>
        ) : (
          <>
            <Alert>
              <AlertTitle>One-time display; boot-time injection only</AlertTitle>
              <AlertDescription>
                The token and generated seed stay only in this component until dismissed or you
                leave, unless you explicitly download them. Four installer formats write the actual
                token into a root-owned 0600 file at first installation; the Nix module uses a
                separately downloaded, target-encrypted systemd credential. Seeds and downloads are
                sensitive. Protect delivery and retained installer logs/cache, remove copied seeds
                after use, and revoke unused tokens before expiry. Never put credentials into
                arguments, environment variables, network URLs, a golden image or the Nix store.
              </AlertDescription>
            </Alert>
            <Label htmlFor="provisioning-secret">Provisioning token secret</Label>
            <Input
              id="provisioning-secret"
              readOnly
              value={result.secret}
              autoComplete="off"
              spellCheck={false}
            />
            <Label htmlFor="provisioning-format">Installer integration</Label>
            <SelectField
              id="provisioning-format"
              value={format}
              options={provisioningFormats}
              onValueChange={(value) => setFormat(value as ProvisioningFormat)}
            />
            <p className="text-sm text-muted-foreground">
              These are integration fragments, not complete OS installer profiles. First install the
              signed agent package and authenticate the deployment root and signed bootstrap bundle.
              The generated boot unit waits up to one hour for approval and same-key issuance, then
              fails visibly rather than claiming enrollment. After resolving an expired wait or
              transient error, start lindm-provision.service again on the same protected
              installation. The token file is removed only after successful installation. For NixOS,
              download the actual token file below and follow the target-local systemd-creds
              encryption procedure included in the module comments.
            </p>
            <Textarea
              aria-label={`${format} provisioning snippet`}
              readOnly
              spellCheck={false}
              className="min-h-96 font-mono text-xs"
              value={provisioningSnippet(format, result.secret)}
            />
            <div className="flex flex-wrap gap-2">
              <Button
                variant="outline"
                onClick={() =>
                  downloadEnrollmentFile(
                    format === "nixos" ? "lindm-enrollment.nix" : `lindm-${format}-sensitive.txt`,
                    provisioningSnippet(format, result.secret),
                  )
                }
              >
                Download {format === "nixos" ? "module" : "sensitive boot input"}
              </Button>
              <Button
                variant="outline"
                onClick={() => downloadEnrollmentFile("provisioning-token", `${result.secret}\n`)}
              >
                Download sensitive token file
              </Button>
            </div>
            <p className="text-sm text-muted-foreground">
              Browser downloads do not enforce Unix permissions. Transfer only through controlled
              custody, install the token as root-owned mode 0600, and remove the browser download
              when delivered.
            </p>
          </>
        )}
        <Button className="w-fit" variant="outline" onClick={onDismiss}>
          Dismiss secret and snippets
        </Button>
      </CardContent>
    </Card>
  );
}
