import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { ArrowLeft, Plus, Shield } from "lucide-react";
import { useId, useRef, useState, type ReactNode } from "react";
import { DeviceState, type Device } from "../../../gen/lindm/admin/v1/admin_pb";
import {
  CollectionStatus,
  SnapshotState,
  type NativeDetails,
} from "../../../gen/lindm/inventory/v1/observation_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { PickerSlot } from "@/components/ui/search-picker";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { canPermission } from "@/lib/permissions";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { toRpcFailure } from "@/lib/errors";
import { RpcError } from "@/components/ui/rpc-error";
import { DeviceLifecycleBadge } from "./lifecycle-badge";
import { DevicePackages } from "./packages";
import type { DeviceTab, PackageSearch } from "./package-search";
import { deviceQueryOptions } from "./queries";
import { CollectionStatusBadge, Fact, ObservedTime, ObservedValue } from "./observations";
import { DeviceMetadataCard } from "./metadata";
import { DeviceNativeDetails, NumberValue } from "./native-details";
import { NativeToolCustodyAlert, ToolCustodyContext } from "./tool-custody";
import { DevicePatchStatus } from "./patch-status";
import { DeviceEncryptionPanel } from "./encryption";
import { DeviceLocalAdminPanel } from "./local-admin";
import { DeviceActionsPanel, DeviceRestrictionBadges } from "./actions";
import { DeviceActionMenu } from "./action-menu";
import { DeviceAgentUpdate } from "./agent-update";
import { DevicePosture } from "./posture";
import { StatusBadge } from "@/components/ui/status-badge";
import { PageHeader } from "@/components/ui/page-header";
import { TechnicalDetails } from "@/components/ui/technical-details";

const snapshotLabels: Record<SnapshotState, string> = {
  [SnapshotState.UNSPECIFIED]: "Not reported",
  [SnapshotState.STAGING]: "Uploading",
  [SnapshotState.COMMITTED]: "Published",
  [SnapshotState.SUPERSEDED]: "Replaced",
  [SnapshotState.EXPIRED]: "Expired",
};

const detailTabs = [
  { id: "overview", label: "Overview" },
  { id: "inventory", label: "Inventory" },
  { id: "resources", label: "Services" },
  { id: "encryption", label: "Encryption" },
  { id: "local-admin", label: "Local admin" },
  { id: "actions", label: "Actions" },
  { id: "assistance", label: "Remote assistance" },
  { id: "findings", label: "Findings" },
] as const;
type DetailTab = DeviceTab;

export function DeviceDetailView({
  deviceId,
  search,
  onSearch,
  resources,
  assignDialog,
  findings,
  findingsSummary,
  compliance,
  revoke,
  assistance,
  accountPicker,
}: {
  deviceId: string;
  search: PackageSearch;
  onSearch: (next: PackageSearch, replace?: boolean) => void;
  resources: (assignProfile: () => void) => ReactNode;
  assignDialog: (open: boolean, onOpenChange: (open: boolean) => void) => ReactNode;
  findings: ReactNode;
  // One-line findings state for the Overview posture section.
  findingsSummary: ReactNode;
  compliance: ReactNode;
  revoke?: (device: Device) => ReactNode;
  // Remote assistance request form and session history, shown on its own tab.
  assistance: ReactNode;
  accountPicker: PickerSlot;
}) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const tabId = useId();
  const tabButtons = useRef<(HTMLButtonElement | null)[]>([]);
  const activeTab = search.tab;
  const [inventoryVisited, setInventoryVisited] = useState(activeTab === "inventory");
  const [assignOpen, setAssignOpen] = useState(false);
  // The open tab lives in the URL so reload, Back and shared links keep it.
  function activateTab(tab: DetailTab) {
    if (tab === "inventory") setInventoryVisited(true);
    if (tab !== activeTab) onSearch({ ...search, tab }, true);
  }
  function openTab(tab: DetailTab) {
    activateTab(tab);
    tabButtons.current[detailTabs.findIndex((item) => item.id === tab)]?.focus();
  }
  const detail = useQuery(deviceQueryOptions(lifetime, deviceId));
  const failure = detail.error ? toRpcFailure(detail.error) : null;
  const data = failure ? undefined : detail.data;
  const device = data?.device;
  const host = data?.host?.observation;
  const attempt = data?.packageAttempt;
  const snapshot = data?.currentSnapshot;
  const storage = host?.details?.storage;
  const hardware = host?.details;
  const disks = storage?.devices.filter(
    (block) => block.type?.status === CollectionStatus.SUCCESS && block.type.value === "disk",
  );
  const root =
    storage?.status === CollectionStatus.SUCCESS
      ? storage.devices.find(
          (block) =>
            block.mountpoint?.status === CollectionStatus.SUCCESS && block.mountpoint.value === "/",
        )
      : undefined;
  const encryption =
    root?.encryption?.status === CollectionStatus.SUCCESS ? root.encryption.value : "";
  const encrypted = ["luks", "dm-crypt", "inherited-dm-crypt"].includes(encryption);
  return (
    <section
      data-review-page="device"
      className="flex min-w-0 flex-col gap-4"
      aria-busy={detail.isFetching}
    >
      <Link
        to="/devices"
        search={{ pageSize: 50, pageToken: "" }}
        className="flex w-fit items-center gap-2 text-sm text-muted-foreground hover:text-foreground focus-visible:underline"
      >
        <ArrowLeft className="size-4" aria-hidden="true" /> Back to devices
      </Link>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <PageHeader title={device?.hostname.trim() || "Unnamed device"} />
          {device ? (
            <div className="mt-3 flex flex-wrap items-center gap-2 text-sm">
              <DeviceLifecycleBadge state={device.lifecycleState} />
              <Badge variant="outline">
                {[device.osId, device.osVersion].filter(Boolean).join(" ") || "OS unknown"}
              </Badge>
              <Badge variant="outline">{device.architecture || "Architecture unknown"}</Badge>
              <Badge variant="outline">
                Contact <ObservedTime value={device.lastSeenAt} server relative />
              </Badge>
              {compliance}
              <Tooltip>
                <TooltipTrigger render={<span tabIndex={0} className="inline-flex" />}>
                  <StatusBadge
                    status={encrypted ? "success" : encryption === "none" ? "warning" : "neutral"}
                  >
                    <Shield aria-hidden="true" />
                    {encrypted
                      ? "Root encrypted"
                      : encryption === "none"
                        ? "Root not encrypted"
                        : "Encryption unknown"}
                  </StatusBadge>
                </TooltipTrigger>
                <TooltipContent>
                  Based on the root disk the device last reported. See Encryption for details.
                </TooltipContent>
              </Tooltip>
              <DeviceRestrictionBadges deviceId={deviceId} />
            </div>
          ) : null}
        </div>
        {/* At most two page actions: Actions and Assign profile. */}
        <div data-review-next-action className="flex flex-wrap items-center gap-2">
          {device ? <DeviceActionMenu device={device} revoke={revoke?.(device)} /> : null}
          {device &&
          device.lifecycleState !== DeviceState.REVOKED &&
          canPermission(principal, "resources.assign") ? (
            <Button variant="outline" aria-haspopup="dialog" onClick={() => setAssignOpen(true)}>
              <Plus aria-hidden="true" /> Assign profile
            </Button>
          ) : null}
        </div>
      </div>
      {device && canPermission(principal, "resources.assign")
        ? assignDialog(assignOpen, setAssignOpen)
        : null}
      {device?.lifecycleState === DeviceState.PENDING ? (
        <Alert>
          <AlertTitle>Waiting for enrollment approval</AlertTitle>
          <AlertDescription>
            This machine asked to enroll and has not reported inventory yet. Approve or reject it in{" "}
            <Link to="/enrollment" className="underline underline-offset-4">
              Enrollment
            </Link>
            .
          </AlertDescription>
        </Alert>
      ) : device?.lifecycleState === DeviceState.REVOKED ? (
        <Alert>
          <AlertTitle>Revoked</AlertTitle>
          <AlertDescription>
            This device can no longer check in or receive actions. Its last reported evidence and
            history stay here for review.
          </AlertDescription>
        </Alert>
      ) : null}
      {failure ? (
        <div data-review-state="blocked">
          <RpcError failure={failure} />
        </div>
      ) : null}
      {detail.isPending ? (
        <p role="status" data-review-state="blocked">
          Loading device…
        </p>
      ) : null}
      {!detail.isPending && !failure && !device ? (
        <p data-review-state="blocked">Device record unavailable. Return to the device list.</p>
      ) : null}
      {device ? (
        <ToolCustodyContext.Provider value={host?.details?.toolCustody}>
          <NativeToolCustodyAlert custody={host?.details?.toolCustody} />
          <div role="tablist" aria-label="Device details" className="flex overflow-x-auto border-b">
            {detailTabs.map((tab, index) => (
              <button
                key={tab.id}
                ref={(element) => {
                  tabButtons.current[index] = element;
                }}
                type="button"
                role="tab"
                id={`${tabId}-${tab.id}-tab`}
                aria-controls={`${tabId}-${tab.id}-panel`}
                aria-selected={activeTab === tab.id}
                tabIndex={activeTab === tab.id ? 0 : -1}
                className="shrink-0 border-b-2 border-transparent px-4 py-3 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground focus-visible:outline focus-visible:outline-ring aria-selected:border-primary aria-selected:text-foreground"
                onClick={() => activateTab(tab.id)}
                onKeyDown={(event) => {
                  let next: number;
                  if (event.key === "ArrowRight") next = (index + 1) % detailTabs.length;
                  else if (event.key === "ArrowLeft")
                    next = (index + detailTabs.length - 1) % detailTabs.length;
                  else if (event.key === "Home") next = 0;
                  else if (event.key === "End") next = detailTabs.length - 1;
                  else return;
                  event.preventDefault();
                  activateTab(detailTabs[next].id);
                  tabButtons.current[next]?.focus();
                }}
              >
                {tab.label}
              </button>
            ))}
          </div>
          <section
            role="tabpanel"
            id={`${tabId}-overview-panel`}
            aria-labelledby={`${tabId}-overview-tab`}
            tabIndex={0}
            hidden={activeTab !== "overview"}
            className="space-y-4"
          >
            <DevicePosture
              device={device}
              rootEncryption={encryption}
              patchStatus={host?.details?.patchStatus}
              inventoryReceivedAt={data?.host?.receivedAt}
              findings={findingsSummary}
              compliance={compliance}
              onOpen={openTab}
            />
            <details className="border-y py-4">
              <summary className="w-fit cursor-pointer text-base font-semibold">
                Hardware and operating system
              </summary>
              <dl className="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                <Fact label="Operating system">
                  <ObservedValue field={host?.osId} />
                </Fact>
                <Fact label="OS version">
                  <ObservedValue field={host?.osVersion} />
                </Fact>
                <Fact label="Kernel">
                  <ObservedValue field={host?.kernelRelease} />
                </Fact>
                <Fact label="Hardware vendor">
                  <ObservedValue field={host?.hardwareVendor} />
                </Fact>
                <Fact label="Model">
                  <ObservedValue field={host?.hardwareModel} />
                </Fact>
                <Fact label="Serial number">
                  <ObservedValue field={host?.hardwareSerial} />
                </Fact>
                <Fact label="CPU">
                  <ObservedValue field={hardware?.cpu?.model} />
                </Fact>
                <Fact label="Logical cores">
                  <NumberValue field={hardware?.cpu?.logicalCores} />
                </Fact>
                <Fact label="RAM">
                  <NumberValue field={hardware?.memory?.totalBytes} unit="bytes" />
                </Fact>
                <Fact label="Disks">
                  {storage?.status === CollectionStatus.SUCCESS ? (
                    disks?.length ? (
                      <ul className="space-y-1">
                        {disks.map((disk) => (
                          <li key={disk.name}>
                            <code className="font-mono">{disk.name}</code>:{" "}
                            <NumberValue field={disk.sizeBytes} unit="bytes" />
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <span>No whole disks reported</span>
                    )
                  ) : (
                    <CollectionStatusBadge status={storage?.status} />
                  )}
                </Fact>
                <Fact label="Root encryption">
                  <ObservedValue field={root?.encryption} />
                </Fact>
              </dl>
            </details>
            <DeviceMetadataCard
              deviceId={deviceId}
              metadata={device.metadata}
              accountPicker={accountPicker}
            />
            <details data-slot="support-details" className="border p-4">
              <summary className="w-fit cursor-pointer font-medium">Details for support</summary>
              <dl className="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                <Fact label="Device ID">{deviceId}</Fact>
                <Fact label="Host sequence">{device.hostSequence.toString()}</Fact>
                <Fact label="Package attempt sequence">{device.packageSequence.toString()}</Fact>
                <Fact label="Published snapshot sequence">
                  {device.publishedSnapshotSequence.toString()}
                </Fact>
                <Fact label="Enrollment generation">{device.enrollmentGeneration}</Fact>
                <Fact label="Agent protocol version">
                  {device.agentVersionAcceptedAt && device.agentProtocolVersion > 0
                    ? device.agentProtocolVersion
                    : "Not reported"}
                </Fact>
                <Fact label="Boot ID">
                  <ObservedValue field={host?.bootId} />
                </Fact>
              </dl>
              <DeviceAgentUpdate
                status={data?.agentUpdate}
                receivedAt={data?.agentUpdateReceivedAt}
              />
            </details>
          </section>
          <section
            role="tabpanel"
            id={`${tabId}-inventory-panel`}
            aria-labelledby={`${tabId}-inventory-tab`}
            tabIndex={0}
            hidden={activeTab !== "inventory"}
            className="space-y-4"
          >
            {inventoryVisited ? (
              <>
                <Card>
                  <CardHeader>
                    <CardTitle>System</CardTitle>
                    <CardDescription>
                      Hardware and operating system as last reported by the device.
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    {host ? (
                      <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                        <Fact label="Reported">
                          <ObservedTime value={data?.host?.receivedAt} server />
                        </Fact>
                        <Fact label="Hostname">
                          <ObservedValue field={host.hostname} />
                        </Fact>
                        <Fact label="Operating system">
                          <ObservedValue field={host.osId} />
                        </Fact>
                        <Fact label="OS version">
                          <ObservedValue field={host.osVersion} />
                        </Fact>
                        <Fact label="Architecture">
                          <ObservedValue field={host.architecture} />
                        </Fact>
                        <Fact label="Kernel">
                          <ObservedValue field={host.kernelRelease} />
                        </Fact>
                        <Fact label="Hardware vendor">
                          <ObservedValue field={host.hardwareVendor} />
                        </Fact>
                        <Fact label="Hardware model">
                          <ObservedValue field={host.hardwareModel} />
                        </Fact>
                        <Fact label="Hardware serial">
                          <ObservedValue field={host.hardwareSerial} />
                        </Fact>
                      </dl>
                    ) : (
                      <p>The device hasn't reported its system details yet.</p>
                    )}
                  </CardContent>
                </Card>
                <AccessAndReporting device={device} details={hardware} />
                <DeviceNativeDetails details={host?.details} osId={host?.osId} />
                <DevicePatchStatus status={host?.details?.patchStatus} />
                <div className="grid gap-4 lg:grid-cols-2">
                  <Card>
                    <CardHeader>
                      <CardTitle>Last package scan</CardTitle>
                      <CardDescription>
                        If a scan fails, the previous package list stays in place.
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      {attempt ? (
                        <dl className="grid gap-4 sm:grid-cols-2">
                          <Fact label="Result">
                            <CollectionStatusBadge status={attempt.status} />
                          </Fact>
                          <Fact label="Package manager">{attempt.backend || "Not reported"}</Fact>
                          <Fact label="Reported">
                            <ObservedTime value={attempt.receivedAt} server />
                          </Fact>
                        </dl>
                      ) : null}
                      {attempt ? (
                        <TechnicalDetails
                          className="mt-3"
                          items={[{ label: "Sequence", value: attempt.sequence.toString() }]}
                        >
                          <dl className="mt-1 grid gap-1">
                            <div>
                              <dt className="inline font-medium">Started (device clock): </dt>
                              <dd className="inline">
                                <ObservedTime value={attempt.startedAt} />
                              </dd>
                            </div>
                            <div>
                              <dt className="inline font-medium">Finished (device clock): </dt>
                              <dd className="inline">
                                <ObservedTime value={attempt.finishedAt} />
                              </dd>
                            </div>
                          </dl>
                        </TechnicalDetails>
                      ) : (
                        <p>No package scan has completed yet.</p>
                      )}
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader>
                      <CardTitle>Installed packages</CardTitle>
                      <CardDescription>The latest complete package list.</CardDescription>
                    </CardHeader>
                    <CardContent>
                      {snapshot ? (
                        <dl className="grid gap-4 sm:grid-cols-2">
                          <Fact label="State">
                            <StatusBadge
                              status={
                                snapshot.state === SnapshotState.COMMITTED
                                  ? "success"
                                  : snapshot.state === SnapshotState.STAGING
                                    ? "info"
                                    : "neutral"
                              }
                            >
                              {snapshotLabels[snapshot.state] ?? "Unknown"}
                            </StatusBadge>
                          </Fact>
                          <Fact label="Packages">{snapshot.packageCount.toLocaleString()}</Fact>
                          <Fact label="Updated">
                            <ObservedTime value={snapshot.committedAt} server />
                          </Fact>
                          {!snapshot.packagesAvailable ? (
                            <Fact label="Package list">
                              No longer stored. Only the count is available.
                            </Fact>
                          ) : null}
                        </dl>
                      ) : (
                        <p>No complete package list yet.</p>
                      )}
                      {snapshot ? (
                        <TechnicalDetails
                          className="mt-3"
                          items={[
                            { label: "Snapshot ID", value: snapshot.snapshotId },
                            { label: "Sequence", value: snapshot.sequence.toString() },
                          ]}
                        />
                      ) : null}
                    </CardContent>
                  </Card>
                </div>
                {data?.stagingSnapshot ? (
                  <Alert>
                    <AlertTitle>Package upload in progress</AlertTitle>
                    <AlertDescription>
                      The device is uploading a new package list. The list below stays in place
                      until the upload completes.
                    </AlertDescription>
                  </Alert>
                ) : null}
                {snapshot || search.pageToken !== "" ? (
                  <DevicePackages
                    key={`${deviceId}:${search.manager}:${search.namePrefix}`}
                    deviceId={deviceId}
                    currentSnapshotSequence={snapshot?.sequence ?? 0n}
                    search={search}
                    onSearch={onSearch}
                  />
                ) : null}
              </>
            ) : null}
          </section>
          <section
            role="tabpanel"
            id={`${tabId}-resources-panel`}
            aria-labelledby={`${tabId}-resources-tab`}
            tabIndex={0}
            hidden={activeTab !== "resources"}
            className="space-y-4"
          >
            {resources(() => setAssignOpen(true))}
            {canPermission(principal, "resources.assign") ? (
              <Link
                to="/rollouts"
                search={{ device: deviceId }}
                className="block w-fit text-sm underline underline-offset-4"
              >
                Preview the settings this device would get
              </Link>
            ) : null}
          </section>
          <section
            role="tabpanel"
            id={`${tabId}-encryption-panel`}
            aria-labelledby={`${tabId}-encryption-tab`}
            tabIndex={0}
            hidden={activeTab !== "encryption"}
            className="space-y-4"
          >
            {activeTab === "encryption" ? (
              <DeviceEncryptionPanel key={`encryption:${deviceId}`} deviceId={deviceId} />
            ) : null}
          </section>
          <section
            role="tabpanel"
            id={`${tabId}-local-admin-panel`}
            aria-labelledby={`${tabId}-local-admin-tab`}
            tabIndex={0}
            hidden={activeTab !== "local-admin"}
            className="space-y-4"
          >
            {activeTab === "local-admin" ? (
              <DeviceLocalAdminPanel key={`local-admin:${deviceId}`} deviceId={deviceId} />
            ) : null}
          </section>
          <section
            role="tabpanel"
            id={`${tabId}-actions-panel`}
            aria-labelledby={`${tabId}-actions-tab`}
            tabIndex={0}
            hidden={activeTab !== "actions"}
            className="space-y-4"
          >
            {activeTab === "actions" ? (
              <DeviceActionsPanel
                key={`actions:${deviceId}`}
                deviceId={deviceId}
                deviceName={device.hostname.trim() || "Unnamed device"}
              />
            ) : null}
          </section>
          <section
            role="tabpanel"
            id={`${tabId}-assistance-panel`}
            aria-labelledby={`${tabId}-assistance-tab`}
            tabIndex={0}
            hidden={activeTab !== "assistance"}
            className="space-y-4"
          >
            {activeTab === "assistance" ? assistance : null}
          </section>
          <section
            role="tabpanel"
            id={`${tabId}-findings-panel`}
            aria-labelledby={`${tabId}-findings-tab`}
            tabIndex={0}
            hidden={activeTab !== "findings"}
            className="space-y-4"
          >
            {findings}
          </section>
        </ToolCustodyContext.Provider>
      ) : null}
    </section>
  );
}

// Users, agent and default-route network summary from the latest inventory.
function AccessAndReporting({
  device,
  details,
}: {
  device: Device;
  details: NativeDetails | undefined;
}) {
  const activeSessions = details?.sessions?.activeSessions;
  const interfaces = details?.network?.interfaces ?? [];
  const defaultInterfaces = interfaces.filter(
    (network) =>
      (network.defaultRouteIpv4?.status === CollectionStatus.SUCCESS &&
        network.defaultRouteIpv4.value) ||
      (network.defaultRouteIpv6?.status === CollectionStatus.SUCCESS &&
        network.defaultRouteIpv6.value),
  );
  const summaryInterfaces = defaultInterfaces.length ? defaultInterfaces : interfaces;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Access and reporting</CardTitle>
        <CardDescription>Who is signed in, the agent version and how it connects.</CardDescription>
      </CardHeader>
      <CardContent>
        <dl className="grid gap-6 sm:grid-cols-2">
          <Fact label="Logged-in users">
            <NumberValue field={details?.sessions?.users} />
            {activeSessions?.status === CollectionStatus.SUCCESS ? (
              activeSessions.sessions.length ? (
                <ul className="mt-2 space-y-1">
                  {activeSessions.sessions.map((session, index) => (
                    <li key={index}>
                      <ObservedValue field={session.userName} />
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="mt-2">No active sessions observed</p>
              )
            ) : (
              <p className="mt-2">
                Active session names: <CollectionStatusBadge status={activeSessions?.status} />
              </p>
            )}
          </Fact>
          <Fact label="Agent version">
            {device.agentVersionAcceptedAt && device.agentRelease ? (
              <div className="grid gap-1">
                <span>{device.agentRelease}</span>
                <span className="text-xs text-muted-foreground">
                  Accepted <ObservedTime value={device.agentVersionAcceptedAt} server />
                </span>
              </div>
            ) : (
              <StatusBadge status="neutral">Not reported</StatusBadge>
            )}
          </Fact>
          <Fact
            label={
              defaultInterfaces.length ? "Default-route IP and MAC" : "Observed network interfaces"
            }
          >
            {details?.network?.status === CollectionStatus.SUCCESS ? (
              interfaces.length ? (
                <ul className="space-y-3">
                  {summaryInterfaces.slice(0, 4).map((network) => (
                    <li key={network.name} className="grid gap-1">
                      <span className="font-medium">{network.name}</span>
                      <span className="text-xs">
                        IPv4 default route:{" "}
                        {network.defaultRouteIpv4?.status === CollectionStatus.SUCCESS ? (
                          network.defaultRouteIpv4.value ? (
                            "Yes"
                          ) : (
                            "No"
                          )
                        ) : (
                          <CollectionStatusBadge status={network.defaultRouteIpv4?.status} />
                        )}
                      </span>
                      <span className="text-xs">
                        IPv6 default route:{" "}
                        {network.defaultRouteIpv6?.status === CollectionStatus.SUCCESS ? (
                          network.defaultRouteIpv6.value ? (
                            "Yes"
                          ) : (
                            "No"
                          )
                        ) : (
                          <CollectionStatusBadge status={network.defaultRouteIpv6?.status} />
                        )}
                      </span>
                      <span>
                        IP:{" "}
                        {network.addresses?.status === CollectionStatus.SUCCESS ? (
                          network.addresses.values.join(", ") || "None observed"
                        ) : (
                          <CollectionStatusBadge status={network.addresses?.status} />
                        )}
                      </span>
                      <span>
                        MAC: <ObservedValue field={network.mac} />
                      </span>
                    </li>
                  ))}
                  {summaryInterfaces.length < interfaces.length || summaryInterfaces.length > 4 ? (
                    <li className="text-muted-foreground">
                      All {interfaces.length} interfaces are listed under Hardware and software.
                    </li>
                  ) : null}
                </ul>
              ) : (
                <span>No interfaces observed</span>
              )
            ) : (
              <CollectionStatusBadge status={details?.network?.status} />
            )}
          </Fact>
        </dl>
      </CardContent>
    </Card>
  );
}
