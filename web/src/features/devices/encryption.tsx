import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { ChevronDown } from "lucide-react";
import { useState, type ReactNode } from "react";
import type { DeviceActionObservation } from "../../../gen/lindm/agent/v1/device_actions_pb";
import type { DeviceRecoveryEscrow } from "../../../gen/lindm/admin/v1/device_actions_pb";
import { RevealApprovalNote } from "@/components/ui/reveal-approval-note";
import { RpcError } from "@/components/ui/rpc-error";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
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
import {
  actionLabels,
  actionPermissions,
  StorageTargetFacts,
  storageTargetDetailItems,
} from "./action-display";
import { deviceActionsQueryOptions, deviceEncryptionQueryOptions } from "./action-queries";
import { Fact, ObservedTime } from "./observations";

// One sentence answering "can this disk be unlocked if the passphrase is lost?",
// from the escrow record and the latest observation of the escrowed volume.
function recoverability(
  volume: DeviceActionObservation | undefined,
  escrow: DeviceRecoveryEscrow | undefined,
  escrowVolume: string,
): ReactNode {
  const tpm = volume?.encrypted
    ? volume.tpm2Bound
      ? "TPM unlock on"
      : "TPM unlock off"
    : "TPM unlock not reported";
  if (!escrow) {
    if (!volume) return "Unknown: no encryption status or recovery key reported yet";
    if (!volume.encrypted)
      return "Not recoverable: the latest report shows this volume isn't encrypted and no recovery key is stored";
    return `Not recoverable: no recovery key escrowed, ${tpm}`;
  }
  if (volume && !volume.encrypted)
    return "Not recoverable: the latest report shows this volume is no longer encrypted";
  if (volume?.occupiedKeyslots.length && !volume.occupiedKeyslots.includes(escrow.keyslot))
    return `Not recoverable: the escrowed key's slot ${escrow.keyslot} is no longer on this volume`;
  return (
    <>
      Recoverable: recovery key{escrowVolume ? ` for ${escrowVolume}` : ""} escrowed{" "}
      <ObservedTime value={escrow.storedAt} server relative />, {tpm}
    </>
  );
}

// A revoked device keeps reveal and recovery re-enrollment; it gets no new actions.
export function DeviceEncryptionPanel({
  deviceId,
  revoked,
}: {
  deviceId: string;
  revoked: boolean;
}) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const navigate = useNavigate();
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
  const volumeOptions = [...volumes].sort().map((uuid, index) => ({
    value: uuid,
    label: `Volume ${index + 1}`,
  }));
  // A single known volume needs no picker; paging stays while older history may hold more.
  const multipleVolumes = volumeOptions.length > 1 || !!luksUuid;
  const morePages = !!volumePageToken || !!history.data?.nextPageToken;
  const escrowVolume =
    !luksUuid && volumeOptions.length > 1
      ? (volumeOptions.find((volume) => volume.value === escrow?.luksUuid)?.label ?? "")
      : "";
  // The verdict and slot facts use the observation only when it describes the escrowed volume;
  // either record may omit its volume, so only two different reported UUIDs disagree.
  const verdictVolume =
    !escrow ||
    !observed?.target?.luksUuid ||
    !escrow.luksUuid ||
    observed.target.luksUuid === escrow.luksUuid
      ? observed
      : undefined;
  // Slot lists are empty when the device did not report them; never present that as "None".
  const slotsReported = !!observed?.occupiedKeyslots.length;
  const escrowSlotPresent = !!escrow && !!verdictVolume?.occupiedKeyslots.includes(escrow.keyslot);
  const canReveal = !!escrow && canPermission(principal, "recovery_keys.read");
  const secondary = [
    ...(["escrowRotate", "tpm2Bind"] as const)
      .filter((kind) => !revoked && canPermission(principal, actionPermissions[kind]))
      .map((kind) => ({
        label: actionLabels[kind],
        open: () =>
          void navigate({
            to: "/devices/$deviceId/actions/new/$kind",
            params: { deviceId, kind },
            search: { luksUuid },
          }),
      })),
    ...(canPermission(principal, "device.revoke")
      ? [
          {
            label: "Recover device enrollment",
            open: () =>
              void navigate({ to: "/devices/$deviceId/recovery-enrollment", params: { deviceId } }),
          },
        ]
      : []),
  ];
  // Without an escrowed key, escrowing one (listed first when permitted) is the next step.
  const primary =
    !escrow && canPermission(principal, actionPermissions.escrowRotate) ? secondary[0] : null;
  const menu = primary ? secondary.slice(1) : secondary;
  const details = [
    ...(multipleVolumes
      ? volumeOptions.map((volume) => ({ label: `${volume.label} LUKS UUID`, value: volume.value }))
      : []),
    ...(observed?.target ? storageTargetDetailItems(observed.target) : []),
    ...(escrow
      ? [
          { label: "Recovery key action ID", value: escrow.actionId },
          { label: "Recovery key slot", value: String(escrow.keyslot) },
          ...(escrow.luksUuid !== observed?.target?.luksUuid
            ? [{ label: "Recovery key LUKS UUID", value: escrow.luksUuid }]
            : []),
        ]
      : []),
    ...(slotsReported
      ? [{ label: "Key slots in use", value: observed?.occupiedKeyslots.join(", ") ?? "" }]
      : []),
    ...(observed?.lindmKeyslots.length
      ? [{ label: "Key slots managed by lindm", value: observed.lindmKeyslots.join(", ") }]
      : slotsReported && !escrowSlotPresent
        ? [{ label: "Key slots managed by lindm", value: "None" }]
        : []),
  ];
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          {failure
            ? "Unknown: encryption status couldn't be loaded"
            : data
              ? recoverability(verdictVolume, escrow, escrowVolume)
              : "Encryption and recovery key"}
        </CardTitle>
      </CardHeader>
      <CardContent className="grid gap-4">
        {query.isPending ? <p role="status">Loading encryption status…</p> : null}
        {failure ? <RpcError failure={failure} /> : null}
        {data ? (
          <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
            {canReveal && escrow ? (
              <Button
                onClick={() =>
                  void navigate({
                    to: "/devices/$deviceId/recovery/$actionId",
                    params: { deviceId, actionId: escrow.actionId },
                  })
                }
              >
                Reveal recovery key
              </Button>
            ) : primary ? (
              <Button onClick={primary.open}>{primary.label}</Button>
            ) : null}
            {canReveal ? <RevealApprovalNote approval={data.recoveryKeyRevealApproval} /> : null}
            {menu.length ? (
              <DropdownMenu>
                <DropdownMenuTrigger render={<Button variant="outline" />}>
                  Other encryption actions <ChevronDown aria-hidden="true" />
                </DropdownMenuTrigger>
                <DropdownMenuContent align="start" className="min-w-56">
                  {menu.map((item) => (
                    <DropdownMenuItem key={item.label} onClick={item.open}>
                      {item.label}
                    </DropdownMenuItem>
                  ))}
                </DropdownMenuContent>
              </DropdownMenu>
            ) : null}
            <Button
              variant="outline"
              disabled={query.isFetching}
              onClick={() => void query.refetch()}
            >
              Refresh
            </Button>
          </div>
        ) : null}
        {multipleVolumes ? (
          <div className="grid gap-2">
            <Label htmlFor={`encryption-volume-${deviceId}`}>Encrypted volume</Label>
            <SelectField
              id={`encryption-volume-${deviceId}`}
              value={luksUuid}
              onValueChange={setLuksUuid}
              options={[{ value: "", label: "Most recent records (any volume)" }, ...volumeOptions]}
            />
          </div>
        ) : null}
        {historyFailure ? (
          <RpcError failure={historyFailure} title="Couldn't load volume history">
            <p>Only the most recently reported volumes are listed.</p>
          </RpcError>
        ) : null}
        {morePages ? (
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
        ) : null}
        {escrow || observed ? (
          <dl className="grid gap-3 sm:grid-cols-2">
            {escrow ? (
              <>
                <Fact label={luksUuid ? "Recovery key for this volume" : "Recovery key stored"}>
                  <ObservedTime value={escrow.storedAt} server />
                </Fact>
                {/* Custody of the escrowed key only; says nothing about old key slots. */}
                <Fact label="Key custody">
                  {escrow.retirementConfirmed ? (
                    "Confirmed by the device"
                  ) : (
                    <StatusBadge status="warning">Not confirmed yet</StatusBadge>
                  )}
                </Fact>
              </>
            ) : null}
            {observed ? (
              <>
                <Fact label={luksUuid ? "Volume reported" : "Volume last reported"}>
                  <ObservedTime value={observed.observedAt} />
                </Fact>
                {observed.encrypted ? null : (
                  <Fact label="Encryption">
                    <StatusBadge status="warning">Not encrypted</StatusBadge>
                  </Fact>
                )}
                <Fact label="TPM 2.0 unlock">{observed.tpm2Bound ? "On" : "Off"}</Fact>
                {observed.supported ? null : (
                  <Fact label="Encryption actions">
                    Not supported{observed.reason ? `: ${observed.reason}` : ""}
                  </Fact>
                )}
                {observed.recoveryEnvironment ? (
                  <Fact label="Boot">
                    <StatusBadge status="warning">Running from lindm recovery</StatusBadge>
                  </Fact>
                ) : null}
              </>
            ) : null}
          </dl>
        ) : null}
        {data && !escrow ? <p className="text-sm">No recovery key stored yet.</p> : null}
        {observed?.target ? <StorageTargetFacts target={observed.target} /> : null}
        {data && !observed ? <p className="text-sm">No encryption status reported yet.</p> : null}
        <TechnicalDetails items={details}>
          {observed?.luksTokens.length ? (
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
          ) : null}
        </TechnicalDetails>
      </CardContent>
    </Card>
  );
}
