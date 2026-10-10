import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { DeviceActionForm } from "./action-form";
import { StorageTargetView } from "./action-display";
import { deviceActionsQueryOptions, deviceEncryptionQueryOptions } from "./action-queries";
import { Fact, ObservedTime } from "./observations";
import { RecoveryKeyReveal } from "./recovery-reveal";

export function DeviceEncryptionPanel({ deviceId }: { deviceId: string }) {
  const lifetime = useAuthLifetime();
  const [luksUuid, setLuksUuid] = useState("");
  const [volumePageToken, setVolumePageToken] = useState("");
  const history = useQuery(deviceActionsQueryOptions(lifetime, deviceId, volumePageToken));
  const historyFailure = history.error ? toRpcFailure(history.error) : null;
  const query = useQuery(deviceEncryptionQueryOptions(lifetime, deviceId, luksUuid));
  const failure = query.error ? toRpcFailure(query.error) : null;
  const data = failure ? undefined : query.data;
  const observed = data?.observation;
  const escrow = data?.escrow;
  const volumes = new Set<string>();
  if (luksUuid) volumes.add(luksUuid);
  if (observed?.target?.luksUuid) volumes.add(observed.target.luksUuid);
  if (escrow?.luksUuid) volumes.add(escrow.luksUuid);
  if (!historyFailure) {
    for (const entry of history.data?.actions ?? []) {
      const action = entry.spec?.action;
      if (
        action?.case === "escrowRotate" ||
        action?.case === "tpm2Bind" ||
        action?.case === "cryptoErase"
      ) {
        if (action.value.target?.luksUuid) volumes.add(action.value.target.luksUuid);
      }
      if (action?.case === "cryptoErase") {
        for (const target of action.value.targets) {
          if (target.luksUuid) volumes.add(target.luksUuid);
        }
      }
    }
  }
  return (
    <Card>
      <CardHeader>
        <CardTitle>Encryption and recovery escrow</CardTitle>
        <CardDescription>
          Select an exact recorded LUKS volume to view its observation and recovery escrow.
        </CardDescription>
        <details className="text-sm text-muted-foreground">
          <summary className="cursor-pointer font-medium">Coverage and custody cautions</summary>
          <p className="mt-2">
            This is not a complete multi-volume inventory or device-wide encryption compliance
            report. Without a selection, the latest observation and escrow can describe different
            volumes. Custody alone does not prove old-slot retirement, current encryption health, or
            deletion of other recovery material.
          </p>
        </details>
      </CardHeader>
      <CardContent className="grid gap-4">
        <div className="grid gap-2">
          <Label htmlFor={`encryption-volume-${deviceId}`}>LUKS volume</Label>
          <SelectField
            id={`encryption-volume-${deviceId}`}
            value={luksUuid}
            onValueChange={setLuksUuid}
            options={[
              { value: "", label: "Latest records across device (not volume-matched)" },
              ...[...volumes].sort().map((uuid) => ({ value: uuid, label: uuid })),
            ]}
          />
          <details className="text-sm text-muted-foreground">
            <summary className="cursor-pointer font-medium">
              Changing volume dismisses a displayed recovery key.
            </summary>
            <p className="mt-2">
              Choices come from real encryption records and this page of action history. Browse
              older action records to find other managed volumes; changing volume dismisses a
              displayed recovery key.
            </p>
          </details>
          {historyFailure ? (
            <p role="alert" className="text-destructive">
              Volume history unavailable: {historyFailure.message}. Only volumes identified by the
              current encryption response can be selected.
            </p>
          ) : null}
          <div className="flex gap-2">
            <Button
              variant="outline"
              disabled={!volumePageToken || history.isFetching}
              onClick={() => setVolumePageToken("")}
            >
              Newest volume records
            </Button>
            <Button
              variant="outline"
              disabled={!!historyFailure || !history.data?.nextPageToken || history.isFetching}
              onClick={() => setVolumePageToken(history.data?.nextPageToken ?? "")}
            >
              Older volume records
            </Button>
          </div>
        </div>
        <Button variant="outline" disabled={query.isFetching} onClick={() => void query.refetch()}>
          Refresh encryption and escrow
        </Button>
        {query.isPending ? <p role="status">Loading encryption custody…</p> : null}
        {failure ? (
          <Alert variant="destructive">
            <AlertTitle>
              {failure.denied ? "Encryption access denied" : "Encryption status unavailable"}
            </AlertTitle>
            <AlertDescription>{failure.message}</AlertDescription>
          </Alert>
        ) : null}
        {observed ? (
          <>
            <h3 className="font-semibold">
              {luksUuid ? "Latest observation for selected volume" : "Latest observed volume"}
            </h3>
            <dl className="grid gap-3 sm:grid-cols-2">
              <Fact label="Observed (device)">
                <ObservedTime value={observed.observedAt} />
              </Fact>
              <Fact label="Last action preflight">
                {observed.supported ? "Supported for its exact action" : "Unsupported"}
                {observed.reason ? ` — ${observed.reason}` : ""}
              </Fact>
              <Fact label="Encrypted target">
                {observed.encrypted ? "Yes" : "No (this observation only)"}
              </Fact>
              <Fact label="TPM 2.0 bound">
                {observed.tpm2Bound ? "Yes" : "No (this observation only)"}
              </Fact>
              <Fact label="lindm-owned keyslots">
                {observed.lindmKeyslots.length
                  ? observed.lindmKeyslots.join(", ")
                  : "None observed"}
              </Fact>
              <Fact label="Recovery environment / off-target journal">
                {observed.recoveryEnvironment ? "Recovery environment" : "Not recovery environment"}{" "}
                / {observed.offTargetJournal ? "Off-target" : "Not off-target"}
              </Fact>
            </dl>
            <dl className="grid gap-3 sm:grid-cols-2">
              <Fact label="All occupied LUKS keyslots">
                {observed.occupiedKeyslots.length
                  ? observed.occupiedKeyslots.join(", ")
                  : "None observed"}
              </Fact>
            </dl>
            {observed.luksTokens.length ? (
              <Table>
                <TableCaption>
                  Public token identifiers and keyslot associations for this observed volume only.
                  Credential material and native token blobs are never included.
                </TableCaption>
                <TableHeader>
                  <TableRow>
                    <TableHead>Token ID</TableHead>
                    <TableHead>Native type</TableHead>
                    <TableHead>Associated keyslots</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {observed.luksTokens.map((token) => (
                    <TableRow key={token.tokenId}>
                      <TableCell>{token.tokenId}</TableCell>
                      <TableCell>{token.type || "Not reported"}</TableCell>
                      <TableCell>
                        {token.keyslots.length ? token.keyslots.join(", ") : "None associated"}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <p>No public LUKS token records were reported for this observation.</p>
            )}
            <StorageTargetView target={observed.target} />
          </>
        ) : data ? (
          <details className="text-sm">
            <summary className="cursor-pointer font-medium">
              No protected encryption action observation is available.
            </summary>
            <p className="mt-2">
              Absence is not proof that storage is unencrypted or that an action is supported.
            </p>
          </details>
        ) : null}
        {escrow ? (
          <>
            <h3 className="font-semibold">
              {luksUuid
                ? "Recovery escrow for selected volume"
                : "Latest recovery escrow — exact LUKS volume"}
            </h3>
            <dl className="grid gap-3 sm:grid-cols-2">
              <Fact label="Escrow action">
                <span className="break-all font-mono text-xs">{escrow.actionId}</span>
              </Fact>
              <Fact label="LUKS UUID">{escrow.luksUuid}</Fact>
              <Fact label="New keyslot">{escrow.keyslot}</Fact>
              <Fact label="Ciphertext stored (server)">
                <ObservedTime value={escrow.storedAt} server />
              </Fact>
              <Fact label="Old managed-slot retirement">
                {escrow.retirementConfirmed
                  ? "Confirmed"
                  : "Not confirmed — custody is not completed rotation"}
              </Fact>
            </dl>
            <RecoveryKeyReveal
              key={`${lifetime.generation}:${deviceId}:${luksUuid}:${escrow.actionId}`}
              deviceId={deviceId}
              actionId={escrow.actionId}
            />
          </>
        ) : data ? (
          <details className="text-sm">
            <summary className="cursor-pointer font-medium">
              No recovery escrow is recorded.
            </summary>
            <p className="mt-2">
              Existing independent owner keys and header backups are not managed by this view.
            </p>
          </details>
        ) : null}
        <DeviceActionForm
          key={`${lifetime.generation}:${deviceId}:${luksUuid}`}
          deviceId={deviceId}
          mode="encryption"
          selectedLuksUuid={luksUuid}
        />
      </CardContent>
    </Card>
  );
}
