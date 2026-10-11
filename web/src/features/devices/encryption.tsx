import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { RpcError } from "@/components/ui/rpc-error";
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
import { usePrincipal } from "@/hooks/use-permissions";
import { canPermission } from "@/lib/permissions";
import { StatusBadge } from "@/components/ui/status-badge";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { actionLabels, actionPermissions, StorageTargetView } from "./action-display";
import { deviceActionsQueryOptions, deviceEncryptionQueryOptions } from "./action-queries";
import { Fact, ObservedTime } from "./observations";

export function DeviceEncryptionPanel({ deviceId }: { deviceId: string }) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
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
        <CardTitle>Encryption and recovery keys</CardTitle>
        <CardDescription>
          Pick a volume to see its encryption status and recovery key.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        <div className="grid gap-2">
          <Label htmlFor={`encryption-volume-${deviceId}`}>Encrypted volume</Label>
          <SelectField
            id={`encryption-volume-${deviceId}`}
            value={luksUuid}
            onValueChange={setLuksUuid}
            options={[
              { value: "", label: "Most recent records (any volume)" },
              ...[...volumes].sort().map((uuid) => ({ value: uuid, label: uuid })),
            ]}
          />
          {historyFailure ? (
            <RpcError failure={historyFailure} title="Couldn't load volume history">
              <p>Only the most recently reported volumes are listed.</p>
            </RpcError>
          ) : null}
          <div className="flex gap-2">
            <Button
              variant="outline"
              disabled={!volumePageToken || history.isFetching}
              onClick={() => setVolumePageToken("")}
            >
              Newest volumes
            </Button>
            <Button
              variant="outline"
              disabled={!!historyFailure || !history.data?.nextPageToken || history.isFetching}
              onClick={() => setVolumePageToken(history.data?.nextPageToken ?? "")}
            >
              Older volumes
            </Button>
          </div>
        </div>
        <Button variant="outline" disabled={query.isFetching} onClick={() => void query.refetch()}>
          Refresh
        </Button>
        {query.isPending ? <p role="status">Loading encryption status…</p> : null}
        {failure ? <RpcError failure={failure} /> : null}
        {observed ? (
          <>
            <h3 className="font-semibold">
              {luksUuid ? "Selected volume" : "Most recently reported volume"}
            </h3>
            <dl className="grid gap-3 sm:grid-cols-2">
              <Fact label="Reported">
                <ObservedTime value={observed.observedAt} />
              </Fact>
              <Fact label="Encryption actions">
                {observed.supported ? "Supported" : "Not supported"}
                {observed.reason ? `: ${observed.reason}` : ""}
              </Fact>
              <Fact label="Encryption">
                <StatusBadge status={observed.encrypted ? "success" : "warning"}>
                  {observed.encrypted ? "Encrypted" : "Not encrypted"}
                </StatusBadge>
              </Fact>
              <Fact label="TPM 2.0 unlock">
                <StatusBadge status={observed.tpm2Bound ? "success" : "neutral"}>
                  {observed.tpm2Bound ? "On" : "Off"}
                </StatusBadge>
              </Fact>
              <Fact label="Key slots managed by lindm">
                {observed.lindmKeyslots.length ? observed.lindmKeyslots.join(", ") : "None"}
              </Fact>
              <Fact label="Running from recovery">
                {observed.recoveryEnvironment ? "Yes" : "No"}
              </Fact>
            </dl>
            <dl className="grid gap-3 sm:grid-cols-2">
              <Fact label="All used key slots">
                {observed.occupiedKeyslots.length
                  ? observed.occupiedKeyslots.join(", ")
                  : "None reported"}
              </Fact>
            </dl>
            {observed.luksTokens.length ? (
              <Table>
                <TableCaption>Unlock tokens on this volume. Secrets are never shown.</TableCaption>
                <TableHeader>
                  <TableRow>
                    <TableHead>Token ID</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Key slots</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {observed.luksTokens.map((token) => (
                    <TableRow key={token.tokenId}>
                      <TableCell>{token.tokenId}</TableCell>
                      <TableCell>{token.type || "Not reported"}</TableCell>
                      <TableCell>
                        {token.keyslots.length ? token.keyslots.join(", ") : "None"}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <p>No unlock tokens reported.</p>
            )}
            <StorageTargetView target={observed.target} />
          </>
        ) : data ? (
          <p className="text-sm">No encryption status reported yet.</p>
        ) : null}
        {escrow ? (
          <>
            <h3 className="font-semibold">
              {luksUuid ? "Recovery key for selected volume" : "Most recent recovery key"}
            </h3>
            <dl className="grid gap-3 sm:grid-cols-2">
              <Fact label="Key slot">{escrow.keyslot}</Fact>
              <Fact label="Stored on server">
                <ObservedTime value={escrow.storedAt} server />
              </Fact>
              <Fact label="Old key removed">
                <StatusBadge status={escrow.retirementConfirmed ? "success" : "warning"}>
                  {escrow.retirementConfirmed ? "Yes" : "Not confirmed"}
                </StatusBadge>
              </Fact>
            </dl>
            <TechnicalDetails
              items={[
                { label: "Action ID", value: escrow.actionId },
                { label: "LUKS UUID", value: escrow.luksUuid },
              ]}
            />
            {canPermission(principal, "recovery_keys.read") ? (
              <Link
                to="/devices/$deviceId/recovery/$actionId"
                params={{ deviceId, actionId: escrow.actionId }}
                className="w-fit text-sm underline"
              >
                Reveal recovery key
              </Link>
            ) : null}
          </>
        ) : data ? (
          <p className="text-sm">No recovery key stored yet.</p>
        ) : null}
        <div className="flex flex-wrap gap-4">
          {(["escrowRotate", "tpm2Bind"] as const)
            .filter((kind) => canPermission(principal, actionPermissions[kind]))
            .map((kind) => (
              <Link
                key={kind}
                to="/devices/$deviceId/actions/new/$kind"
                params={{ deviceId, kind }}
                search={{ luksUuid }}
                className="text-sm underline"
              >
                {actionLabels[kind]}
              </Link>
            ))}
          {canPermission(principal, "device.revoke") ? (
            <Link
              to="/devices/$deviceId/recovery-enrollment"
              params={{ deviceId }}
              className="text-sm underline"
            >
              Recover device enrollment
            </Link>
          ) : null}
        </div>
      </CardContent>
    </Card>
  );
}
