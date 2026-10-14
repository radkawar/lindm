// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { useQueryClient } from "@tanstack/react-query";
import { useId, useState, type FormEvent } from "react";
import {
  ConfirmRecoveryKeyCustodyRequestSchema,
  RecoveryKeyCustodyExportKind,
  RecoveryKeyCustodyState,
  type ConfirmRecoveryKeyCustodyRequest,
  type RecoveryKeyCustody,
} from "../../../gen/lindm/admin/v1/server_status_pb";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { RpcError } from "@/components/ui/rpc-error";
import { StatusBadge } from "@/components/ui/status-badge";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { Timestamp } from "@/components/ui/timestamp";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { useExactRequest } from "@/hooks/use-exact-request";
import { adminClient } from "@/lib/rpc";
import { validateRequest } from "@/lib/validation";

export function RecoveryCustodyTask({
  custody,
  stale,
}: {
  custody?: RecoveryKeyCustody;
  stale: boolean;
}) {
  const lifetime = useAuthLifetime();
  const queryClient = useQueryClient();
  const exact = useExactRequest<ConfirmRecoveryKeyCustodyRequest>();
  const [open, setOpen] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const checkboxId = useId();
  const headingId = useId();
  const state = custody?.state ?? RecoveryKeyCustodyState.UNKNOWN;
  const pending = state === RecoveryKeyCustodyState.PENDING;
  const recorded = state === RecoveryKeyCustodyState.CONFIRMED;
  const external = state === RecoveryKeyCustodyState.EXTERNAL_RECIPIENTS;
  const canConfirm = pending && custody?.canConfirm && !stale;

  function record(event?: FormEvent<HTMLFormElement>) {
    event?.preventDefault();
    if (!canConfirm || !confirmed || !custody) return;
    void exact.submit({
      capture: () => {
        const request = create(ConfirmRecoveryKeyCustodyRequestSchema, {
          expectedConfirmationDigest: custody.confirmationDigest,
          confirmOffServerCustody: confirmed,
        });
        validateRequest(ConfirmRecoveryKeyCustodyRequestSchema, request);
        return request;
      },
      send: (request, options) => adminClient.confirmRecoveryKeyCustody(request, options),
      failureTitle: "Recovery custody confirmation",
      onSuccess: async () => {
        setOpen(false);
        await queryClient.invalidateQueries({ queryKey: ["server-status", lifetime.generation] });
      },
    });
  }

  return (
    <section
      aria-labelledby={headingId}
      data-slot="recovery-custody-task"
      className={`grid min-w-0 gap-3 border-l-2 pl-4 ${pending ? "border-warning" : "border-border"}`}
    >
      <div className="flex flex-wrap items-center gap-2">
        <h2 id={headingId} className="text-base font-semibold">
          {pending
            ? "Move your recovery keys off this server"
            : recorded
              ? "Owner confirmation recorded"
              : external
                ? "Recovery keys use external recipients"
                : "Recovery custody needs evidence"}
        </h2>
        <StatusBadge status={pending ? "warning" : "neutral"}>
          {pending
            ? "Action required"
            : recorded
              ? "Recorded"
              : external
                ? "External recipients"
                : "Unknown"}
        </StatusBadge>
      </div>
      <p className="text-sm">
        {pending
          ? "Move every listed encrypted export to protected storage away from this server. Keep each file's passphrase separately."
          : recorded
            ? "An owner recorded custody for this export set. lindm does not verify storage or removal."
            : external
              ? "This installation used external recovery recipients. Keep the matching recovery identities away from this server."
              : "Inspect the protected custody record and installation journal."}
      </p>
      {custody?.recordedAt ? (
        <p className="text-xs text-muted-foreground">
          Evidence recorded: <Timestamp value={custody.recordedAt} />
        </p>
      ) : null}
      {recorded && custody?.confirmedAt ? (
        <p className="text-xs text-muted-foreground">
          Owner confirmation: <Timestamp value={custody.confirmedAt} />
        </p>
      ) : null}
      {stale ? (
        <p className="text-sm text-muted-foreground">
          Refresh before recording a custody confirmation.
        </p>
      ) : null}
      {pending && !custody?.canConfirm ? (
        <p className="text-sm text-muted-foreground">
          Only the deployment owner can record this confirmation.
        </p>
      ) : null}
      {pending && custody?.canConfirm ? (
        <Button type="button" className="w-fit" disabled={stale} onClick={() => setOpen(true)}>
          Confirm off-server custody
        </Button>
      ) : null}
      {(pending || recorded) && custody ? (
        <TechnicalDetails
          items={[{ label: "Confirmation digest", value: custody.confirmationDigest }]}
        >
          <div className="mt-3 grid min-w-0 gap-3">
            {custody.exports.map((exportFile) => (
              <div
                key={exportFile.path}
                data-slot="recovery-custody-export"
                className="grid min-w-0 gap-2"
              >
                <h3 className="text-sm font-medium">
                  {exportFile.kind === RecoveryKeyCustodyExportKind.FRESH_DATABASE
                    ? "Fresh database recovery identity"
                    : "Server recovery identities"}
                </h3>
                <p>Keep this file's passphrase separately.</p>
                <dl className="grid min-w-0 gap-1 break-all">
                  <div>
                    <dt className="inline font-medium">Protected encrypted export: </dt>
                    <dd className="inline font-mono">{exportFile.path}</dd>
                  </div>
                  <div>
                    <dt className="inline font-medium">File checksum: </dt>
                    <dd className="inline font-mono">{exportFile.sha256}</dd>
                  </div>
                  <div>
                    <dt className="inline font-medium">Local ciphertext copy: </dt>
                    <dd className="inline">
                      {exportFile.localPresent ? "Present" : "Not present"}
                    </dd>
                  </div>
                </dl>
              </div>
            ))}
          </div>
        </TechnicalDetails>
      ) : null}
      <Dialog
        open={open}
        onOpenChange={(next) => {
          if (!exact.busy) setOpen(next);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Confirm off-server custody</DialogTitle>
            <DialogDescription>
              Your confirmation applies only to the complete current export set.
            </DialogDescription>
          </DialogHeader>
          <form className="grid gap-4" onSubmit={record}>
            <p className="text-sm">
              lindm records your attestation. It does not verify external storage or removal.
            </p>
            <div className="flex items-start gap-2">
              <input
                id={checkboxId}
                type="checkbox"
                className="mt-1 shrink-0 accent-primary"
                checked={confirmed}
                disabled={exact.busy || exact.ambiguous}
                onChange={(event) => setConfirmed(event.target.checked)}
              />
              <Label htmlFor={checkboxId}>
                I stored every listed recovery export off this server.
              </Label>
            </div>
            {exact.invalid ? (
              <p role="alert" className="text-sm text-destructive">
                {exact.invalid}
              </p>
            ) : null}
            {exact.failure ? (
              <RpcError
                failure={exact.failure}
                title="Custody confirmation not recorded"
                onRetry={() => record()}
                recoveryCustodyConfirmationDigest={custody?.confirmationDigest}
              />
            ) : null}
            {exact.ambiguous ? (
              <p className="text-sm">
                Refresh to check the outcome. Retry this same confirmation before starting another.
              </p>
            ) : null}
            <div className="flex flex-wrap gap-2">
              <Button type="submit" disabled={!canConfirm || !confirmed || exact.busy}>
                {exact.busy
                  ? "Recording…"
                  : exact.ambiguous
                    ? "Retry confirmation"
                    : "Record my confirmation"}
              </Button>
              <Button
                type="button"
                variant="outline"
                disabled={exact.busy}
                onClick={() => setOpen(false)}
              >
                Cancel
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </section>
  );
}
