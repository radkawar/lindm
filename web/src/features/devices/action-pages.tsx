import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import type { ReactNode } from "react";
import type { Device } from "../../../gen/lindm/admin/v1/admin_pb";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { DeviceActionForm } from "./action-form";
import { actionLabels } from "./action-display";
import type { ComplexActionKind } from "./action-menu";
import { DeviceActionResult } from "./actions";
import { deviceActionQueryOptions } from "./action-queries";
import { deviceQueryOptions } from "./queries";
import { Fact } from "./observations";
import { RecoveryKeyReveal } from "./recovery-reveal";

export function DeviceActionPage({
  deviceId,
  title,
  description = "Check the device and fill in the details.",
  children,
}: {
  deviceId: string;
  title: string;
  description?: string;
  children: (device: Device) => ReactNode;
}) {
  const lifetime = useAuthLifetime();
  const detail = useQuery(deviceQueryOptions(lifetime, deviceId));
  const device = detail.error ? undefined : detail.data?.device;
  return (
    <section className="grid min-w-0 max-w-5xl gap-4">
      <nav aria-label="Device action breadcrumbs" className="flex flex-wrap gap-2 text-sm">
        <Link to="/devices" className="underline">
          Devices
        </Link>
        <span aria-hidden="true">/</span>
        <Link to="/devices/$deviceId" params={{ deviceId }} className="underline">
          {device?.hostname.trim() || "Unnamed device"}
        </Link>
        <span aria-hidden="true">/</span>
        <span aria-current="page">{title}</span>
      </nav>
      <PageHeader title={title} description={description} />
      {detail.error ? <RpcError failure={toRpcFailure(detail.error)} /> : null}
      {detail.isPending ? <p role="status">Loading device…</p> : null}
      {device ? (
        <>
          <Card>
            <CardHeader>
              <CardTitle>Device</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-3">
              <dl className="grid gap-3 break-all text-sm sm:grid-cols-2">
                <Fact label="Hostname">{device.hostname.trim() || "Unnamed device"}</Fact>
                <Fact label="Operating system">
                  {[device.osId, device.osVersion].filter(Boolean).join(" ") || "Not reported"}
                </Fact>
              </dl>
              <TechnicalDetails
                items={[
                  { label: "Device ID", value: device.id },
                  { label: "Enrollment generation", value: String(device.enrollmentGeneration) },
                ]}
              />
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
    <DeviceActionPage deviceId={deviceId} title={actionLabels[kind]}>
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

export function DeviceActionStatusPage({
  deviceId,
  actionId,
}: {
  deviceId: string;
  actionId: string;
}) {
  const lifetime = useAuthLifetime();
  const query = useQuery(deviceActionQueryOptions(lifetime, deviceId, actionId));
  return (
    <DeviceActionPage
      deviceId={deviceId}
      title="Action status"
      description="Progress and result of this action."
    >
      {() => (
        <div className="grid gap-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <Button
              variant="outline"
              disabled={query.isFetching}
              onClick={() => void query.refetch()}
            >
              Refresh
            </Button>
          </div>
          {query.isPending ? <p role="status">Loading action result…</p> : null}
          {query.error ? (
            <RpcError failure={toRpcFailure(query.error)} />
          ) : query.data ? (
            <DeviceActionResult action={query.data} linked={false} />
          ) : null}
          <Link to="/devices/$deviceId" params={{ deviceId }} className="w-fit text-sm underline">
            Back to device
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
      {() => (
        <div className="grid gap-4">
          {query.isPending ? <p role="status">Loading recovery key record…</p> : null}
          {query.error ? <RpcError failure={toRpcFailure(query.error)} /> : null}
          {action ? (
            <>
              <DeviceActionResult action={action} linked={false} />
              {action.spec?.action.case === "escrowRotate" ? (
                <Card>
                  <CardHeader>
                    <CardTitle>Recovery access</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <RecoveryKeyReveal
                      key={`${lifetime.generation}:${deviceId}:${actionId}`}
                      deviceId={deviceId}
                      actionId={actionId}
                    />
                  </CardContent>
                </Card>
              ) : (
                <p>
                  This action doesn&apos;t have a recovery key. Pick a recovery key from the
                  Encryption tab.
                </p>
              )}
            </>
          ) : null}
        </div>
      )}
    </DeviceActionPage>
  );
}
