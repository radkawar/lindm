import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { ArrowLeft } from "lucide-react";
import { useId, type ReactNode } from "react";
import type { Device } from "../../../gen/lindm/admin/v1/admin_pb";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { DeviceActionForm } from "./action-form";
import { actionLabels } from "./action-display";
import type { ComplexActionKind } from "./action-menu";
import { DeviceActionResult } from "./actions";
import { deviceActionQueryOptions } from "./action-queries";
import { deviceQueryOptions } from "./queries";
import { Fact } from "./observations";
import { deviceOsLabel } from "./os";
import { RecoveryKeyReveal } from "./recovery-reveal";

export function DeviceActionPage({
  deviceId,
  title,
  description,
  actions,
  lead,
  children,
}: {
  deviceId: string;
  title: string;
  description?: string;
  actions?: ReactNode;
  // Rendered before the device and every input, e.g. a destructive action's consequences.
  lead?: (device: Device) => ReactNode;
  children: (device: Device) => ReactNode;
}) {
  const lifetime = useAuthLifetime();
  const detail = useQuery(deviceQueryOptions(lifetime, deviceId));
  const device = detail.error ? undefined : detail.data?.device;
  return (
    <section className="grid min-w-0 max-w-5xl gap-4">
      <Link
        to="/devices/$deviceId"
        params={{ deviceId }}
        className="flex w-fit items-center gap-2 text-sm text-muted-foreground hover:text-foreground focus-visible:underline"
      >
        <ArrowLeft className="size-4" aria-hidden="true" /> Back to{" "}
        {device?.hostname.trim() || "device"}
      </Link>
      <PageHeader title={title} description={description} actions={actions} />
      {detail.error ? <RpcError failure={toRpcFailure(detail.error)} /> : null}
      {detail.isPending ? <p role="status">Loading device…</p> : null}
      {device ? (
        <>
          {lead?.(device)}
          <Card>
            <CardHeader>
              <CardTitle>Device</CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="grid gap-3 break-all text-sm sm:grid-cols-2">
                <Fact label="Hostname">{device.hostname.trim() || "Unnamed device"}</Fact>
                <Fact label="Operating system">{deviceOsLabel(device) || "Not reported"}</Fact>
              </dl>
            </CardContent>
          </Card>
          {children(device)}
        </>
      ) : null}
    </section>
  );
}

export function DeviceActionCreatePage({
  deviceId,
  kind,
  luksUuid,
}: {
  deviceId: string;
  kind: ComplexActionKind;
  luksUuid: string;
}) {
  const lifetime = useAuthLifetime();
  const navigate = useNavigate();
  return (
    <DeviceActionPage
      deviceId={deviceId}
      title={actionLabels[kind]}
      lead={
        kind === "cryptoErase" || kind === "sanitize"
          ? (device) => <DestructiveConsequences kind={kind} hostname={device.hostname.trim()} />
          : undefined
      }
    >
      {() => (
        <Card>
          <CardContent className="pt-6">
            <DeviceActionForm
              key={`${lifetime.generation}:${deviceId}:${kind}:${luksUuid}`}
              deviceId={deviceId}
              mode={kind === "escrowRotate" || kind === "tpm2Bind" ? "encryption" : "actions"}
              kind={kind}
              selectedLuksUuid={luksUuid}
              onCreated={(actionId) =>
                void navigate({
                  to: "/devices/$deviceId/actions/$actionId",
                  params: { deviceId, actionId },
                })
              }
            />
          </CardContent>
        </Card>
      )}
    </DeviceActionPage>
  );
}

// What a destructive action does, stated before any choice. Facts follow the
// executor and server: crypto erase overwrites the LUKS header and keyslot area,
// then powers off; escrow and header backups are untouched; admission needs
// contact within a minute and the console's request expires 10 minutes after review.
function DestructiveConsequences({
  kind,
  hostname,
}: {
  kind: "cryptoErase" | "sanitize";
  hostname: string;
}) {
  const id = useId();
  const wipe = kind === "cryptoErase";
  const target = hostname || "this device";
  const subject = hostname || "The device";
  return (
    <section
      aria-labelledby={id}
      data-slot="action-consequences"
      className="grid gap-2 rounded-lg border border-destructive/50 p-4 text-sm"
    >
      <h2 id={id} className="text-base font-semibold text-destructive">
        {wipe ? "Wiping can't be undone" : "Erasing can't be undone"}
      </h2>
      <ul className="grid list-disc gap-1 pl-5">
        {wipe ? (
          <>
            <li>
              Destroys the encryption header and key slots of the volumes you select on {target}.
              Their data becomes unreadable.
            </li>
            <li>{subject} powers off when the wipe finishes.</li>
          </>
        ) : (
          <>
            <li>Erases everything on the unencrypted disk you select on {target}.</li>
            <li>
              If you choose to boot into lindm recovery first, {target} restarts into recovery and
              powers off when the erase finishes.
            </li>
          </>
        )}
        <li>Another admin must approve this {wipe ? "wipe" : "erase"} before you can send it.</li>
        <li>
          {wipe
            ? "Not destroyed: recovery keys escrowed on this server and any header backups. Anyone with a header backup and a recovery key can still read the data."
            : "Not erased: backups and snapshots stored elsewhere."}
        </li>
        <li>
          The device must be online: sending is refused unless it checked in during the last minute.
          If it hasn&apos;t started within 10 minutes of your review, the request expires and
          nothing is {wipe ? "wiped" : "erased"}.
        </li>
      </ul>
    </section>
  );
}

export function DeviceActionStatusPage({
  deviceId,
  actionId,
}: {
  deviceId: string;
  actionId: string;
}) {
  const lifetime = useAuthLifetime();
  const query = useQuery(deviceActionQueryOptions(lifetime, deviceId, actionId));
  const kind = query.data?.spec?.action.case;
  return (
    <DeviceActionPage
      deviceId={deviceId}
      title={kind ? actionLabels[kind] : "Action status"}
      description="Progress and result as the device reported it."
      actions={
        <Button variant="outline" disabled={query.isFetching} onClick={() => void query.refetch()}>
          {query.isFetching ? "Refreshing…" : "Refresh"}
        </Button>
      }
    >
      {() => (
        <div className="grid gap-4">
          {query.isPending ? <p role="status">Loading action result…</p> : null}
          {query.error ? (
            <RpcError failure={toRpcFailure(query.error)} />
          ) : query.data ? (
            <DeviceActionResult action={query.data} linked={false} />
          ) : null}
          <Link
            to="/devices/$deviceId"
            params={{ deviceId }}
            search={{ tab: "actions" }}
            className="w-fit text-sm underline"
          >
            See all actions on this device
          </Link>
        </div>
      )}
    </DeviceActionPage>
  );
}

export function DeviceRecoveryRevealPage({
  deviceId,
  actionId,
}: {
  deviceId: string;
  actionId: string;
}) {
  const lifetime = useAuthLifetime();
  const query = useQuery(deviceActionQueryOptions(lifetime, deviceId, actionId));
  const action = query.error ? undefined : query.data;
  return (
    <DeviceActionPage
      deviceId={deviceId}
      title="Reveal recovery key"
      description="Get access to the recovery key for this volume."
    >
      {(device) => (
        <div className="grid gap-4">
          {query.isPending ? <p role="status">Loading recovery key record…</p> : null}
          {query.error ? <RpcError failure={toRpcFailure(query.error)} /> : null}
          {action ? (
            action.spec?.action.case === "escrowRotate" ? (
              <Card>
                <CardHeader>
                  <CardTitle>Recovery access</CardTitle>
                </CardHeader>
                <CardContent>
                  <RecoveryKeyReveal
                    key={`${lifetime.generation}:${deviceId}:${actionId}`}
                    deviceId={deviceId}
                    deviceName={device.hostname}
                    actionId={actionId}
                  />
                </CardContent>
              </Card>
            ) : (
              <p>
                This action doesn&apos;t have a recovery key. Pick a recovery key from the
                Encryption tab.
              </p>
            )
          ) : null}
        </div>
      )}
    </DeviceActionPage>
  );
}
