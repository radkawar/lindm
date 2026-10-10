import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { ArrowLeft, LockKeyhole, Plus, RefreshCw, Shield, Trash2 } from "lucide-react";
import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import type { Device } from "../../../gen/lindm/admin/v1/admin_pb";
import { CollectionStatus, SnapshotState } from "../../../gen/lindm/inventory/v1/observation_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { canPermission } from "@/lib/permissions";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { toRpcFailure } from "@/lib/errors";
import { DeviceLifecycleBadge } from "./lifecycle-badge";
import { DevicePackages } from "./packages";
import type { PackageSearch } from "./package-search";
import { deviceQueryOptions } from "./queries";
import { collectionLabels, Fact, ObservedTime, ObservedValue } from "./observations";
import { DeviceMetadataCard } from "./metadata";
import { DeviceNativeDetails } from "./native-details";
import { DeviceEncryptionPanel } from "./encryption";
import { DeviceActionsPanel, DeviceLockRestriction } from "./actions";

const snapshotLabels: Record<SnapshotState, string> = {
  [SnapshotState.UNSPECIFIED]: "Not reported",
  [SnapshotState.STAGING]: "Upload in progress — not published",
  [SnapshotState.COMMITTED]: "Published",
  [SnapshotState.SUPERSEDED]: "Superseded",
  [SnapshotState.EXPIRED]: "Expired",
};

const detailTabs = [
  { id: "overview", label: "Overview" },
  { id: "inventory", label: "Inventory" },
  { id: "resources", label: "Resources / Compliance" },
  { id: "actions", label: "Encryption / Actions" },
  { id: "findings", label: "Findings" },
  { id: "history", label: "History" },
] as const;
type DetailTab = (typeof detailTabs)[number]["id"];

export function DeviceDetailView({
  deviceId,
  search,
  onSearch,
  resources,
  findings,
  history,
  compliance,
  enrollmentRecovery,
}: {
  deviceId: string;
  search: PackageSearch;
  onSearch: (next: PackageSearch, replace?: boolean) => void;
  resources: (assignProfile: () => void) => ReactNode;
  findings: ReactNode;
  history: ReactNode;
  compliance: ReactNode;
  enrollmentRecovery?: (device: Device) => ReactNode;
}) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const tabId = useId();
  const tabButtons = useRef<(HTMLButtonElement | null)[]>([]);
  const [activeTab, setActiveTab] = useState<DetailTab>(
    search.pageToken || search.manager || search.namePrefix ? "inventory" : "overview",
  );
  const [inventoryVisited, setInventoryVisited] = useState(activeTab === "inventory");
  const [focusTarget, setFocusTarget] = useState<"resources" | "actions" | null>(null);
  useEffect(() => {
    if (!focusTarget) return;
    const target =
      focusTarget === "resources" ? "resource-profile" : `action-actions-${deviceId}-kind`;
    const frame = requestAnimationFrame(() => {
      const control = document.getElementById(target);
      const panel = document.getElementById(`${tabId}-${focusTarget}-panel`);
      const destination = control && !control.hasAttribute("disabled") ? control : panel;
      destination?.focus();
      destination?.scrollIntoView({ block: "center", behavior: "smooth" });
      setFocusTarget(null);
    });
    return () => cancelAnimationFrame(frame);
  }, [focusTarget, activeTab, deviceId, tabId]);
  function activateTab(tab: DetailTab) {
    setActiveTab(tab);
    if (tab === "inventory") setInventoryVisited(true);
  }
  function openForm(tab: "resources" | "actions") {
    activateTab(tab);
    setFocusTarget(tab);
  }
  const detail = useQuery(deviceQueryOptions(lifetime, deviceId));
  const failure = detail.error ? toRpcFailure(detail.error) : null;
  const data = failure ? undefined : detail.data;
  const device = data?.device;
  const host = data?.host?.observation;
  const attempt = data?.packageAttempt;
  const snapshot = data?.currentSnapshot;
  const storage = host?.details?.storage;
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
    <section className="flex min-w-0 flex-col gap-4" aria-busy={detail.isFetching}>
      <Link
        to="/devices"
        search={{ pageSize: 50, pageToken: "" }}
        className="flex w-fit items-center gap-2 text-sm text-muted-foreground hover:text-foreground focus-visible:underline"
      >
        <ArrowLeft className="size-4" aria-hidden="true" /> Back to devices
      </Link>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="break-words text-2xl font-semibold tracking-tight">
            {device?.hostname.trim() || "Device inventory"}
          </h1>
          <p className="break-all font-mono text-xs text-muted-foreground">{deviceId}</p>
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
                <TooltipTrigger
                  render={
                    <Badge
                      variant={
                        encrypted ? "success" : encryption === "none" ? "warning" : "outline"
                      }
                      tabIndex={0}
                    />
                  }
                >
                  <Shield aria-hidden="true" />
                  {encrypted
                    ? "Root encrypted"
                    : encryption === "none"
                      ? "Root not encrypted"
                      : "Encryption unknown"}
                </TooltipTrigger>
                <TooltipContent>
                  Latest device-reported root filesystem storage observation, not full-disk
                  coverage, escrow readiness, or live state. Inspect Inventory and Encryption /
                  Actions for exact evidence.
                </TooltipContent>
              </Tooltip>
            </div>
          ) : null}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant="outline"
            disabled={detail.isFetching}
            onClick={() => void detail.refetch()}
          >
            <RefreshCw aria-hidden="true" /> Refresh
          </Button>
          {device && canPermission(principal, "actions.lock") ? (
            <Button variant="outline" onClick={() => openForm("actions")}>
              <LockKeyhole aria-hidden="true" /> Lock…
            </Button>
          ) : null}
          {device && canPermission(principal, "actions.release-lock") ? (
            <Button variant="outline" onClick={() => openForm("actions")}>
              Release lock…
            </Button>
          ) : null}
          {device && canPermission(principal, "destructive.execute") ? (
            <Button variant="outline" onClick={() => openForm("actions")}>
              <Trash2 aria-hidden="true" /> Wipe…
            </Button>
          ) : null}
          {device && canPermission(principal, "resources.assign") ? (
            <Button onClick={() => openForm("resources")}>
              <Plus aria-hidden="true" /> Assign profile
            </Button>
          ) : null}
        </div>
      </div>
      {failure ? (
        <Alert variant="destructive">
          <AlertTitle>{failure.denied ? "Not authorized" : "Device detail unavailable"}</AlertTitle>
          <AlertDescription>
            {failure.codeName}: {failure.message}
          </AlertDescription>
        </Alert>
      ) : null}
      {detail.isPending ? <p role="status">Loading device inventory…</p> : null}
      {device ? (
        <>
          <DeviceLockRestriction deviceId={deviceId} />
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
            <Card>
              <CardHeader>
                <CardTitle>Identity and contact</CardTitle>
                <CardDescription>Device identity and its latest accepted contact.</CardDescription>
              </CardHeader>
              <CardContent>
                <details className="mb-4 text-xs text-muted-foreground">
                  <summary className="w-fit cursor-pointer">
                    How to interpret these observations
                  </summary>
                  <p className="mt-2">
                    Contact is not inventory freshness, online presence, or compliance.
                  </p>
                </details>
                <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                  <Fact label="Lifecycle">
                    <DeviceLifecycleBadge state={device.lifecycleState} />
                  </Fact>
                  <Fact label="Last contact (server)">
                    <ObservedTime value={device.lastSeenAt} server />
                  </Fact>
                  <Fact label="Host sequence">{device.hostSequence.toString()}</Fact>
                  <Fact label="Package attempt sequence">{device.packageSequence.toString()}</Fact>
                  <Fact label="Published snapshot sequence">
                    {device.publishedSnapshotSequence.toString()}
                  </Fact>
                </dl>
              </CardContent>
            </Card>
            <DeviceMetadataCard deviceId={deviceId} metadata={device.metadata} />
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
                    <CardTitle>Host observations</CardTitle>
                    <CardDescription>
                      Device-reported hardware and operating system inventory.
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <details className="mb-4 text-xs text-muted-foreground">
                      <summary className="w-fit cursor-pointer">Observation caveats</summary>
                      <p className="mt-2">
                        Collection times and values are device-reported. Missing or failed fields
                        are not successful empty values.
                      </p>
                    </details>
                    {host ? (
                      <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                        <Fact label="Collection started (device)">
                          <ObservedTime value={host.startedAt} />
                        </Fact>
                        <Fact label="Collection finished (device)">
                          <ObservedTime value={host.finishedAt} />
                        </Fact>
                        <Fact label="Received (server)">
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
                        <Fact label="Boot ID">
                          <ObservedValue field={host.bootId} />
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
                      <p>No host observation has been accepted.</p>
                    )}
                  </CardContent>
                </Card>
                <DeviceNativeDetails details={host?.details} />
                <div className="grid gap-4 lg:grid-cols-2">
                  <Card>
                    <CardHeader>
                      <CardTitle>Latest completed package attempt</CardTitle>
                      <CardDescription>
                        Result of the most recent completed package collection.
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <details className="mb-4 text-xs text-muted-foreground">
                        <summary className="w-fit cursor-pointer">Collection and freshness</summary>
                        <p className="mt-2">
                          A failed collection preserves the last published inventory and its
                          original freshness.
                        </p>
                      </details>
                      {attempt ? (
                        <dl className="grid gap-4 sm:grid-cols-2">
                          <Fact label="Result">
                            <Badge
                              variant={
                                attempt.status === CollectionStatus.SUCCESS
                                  ? "outline"
                                  : "destructive"
                              }
                            >
                              {collectionLabels[attempt.status] ?? "Unknown collection status"}
                            </Badge>
                          </Fact>
                          <Fact label="Sequence">{attempt.sequence.toString()}</Fact>
                          <Fact label="Backend">{attempt.backend || "Not reported"}</Fact>
                          <Fact label="Collection started (device)">
                            <ObservedTime value={attempt.startedAt} />
                          </Fact>
                          <Fact label="Collection finished (device)">
                            <ObservedTime value={attempt.finishedAt} />
                          </Fact>
                          <Fact label="Received (server)">
                            <ObservedTime value={attempt.receivedAt} server />
                          </Fact>
                        </dl>
                      ) : (
                        <p>No completed package attempt has been accepted.</p>
                      )}
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader>
                      <CardTitle>Latest published package inventory</CardTitle>
                      <CardDescription>
                        The latest complete published package snapshot.
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <details className="mb-4 text-xs text-muted-foreground">
                        <summary className="w-fit cursor-pointer">Publication requirements</summary>
                        <p className="mt-2">
                          Only a complete committed snapshot is inventory. Partial uploads are never
                          shown as complete.
                        </p>
                      </details>
                      {snapshot ? (
                        <dl className="grid gap-4 sm:grid-cols-2">
                          <Fact label="State">
                            {snapshotLabels[snapshot.state] ?? "Unknown snapshot state"}
                          </Fact>
                          <Fact label="Packages">{snapshot.packageCount.toLocaleString()}</Fact>
                          <Fact label="Snapshot ID">
                            <span className="break-all font-mono text-xs">
                              {snapshot.snapshotId}
                            </span>
                          </Fact>
                          <Fact label="Sequence">{snapshot.sequence.toString()}</Fact>
                          <Fact label="Collection finished (device)">
                            <ObservedTime value={snapshot.finishedAt} />
                          </Fact>
                          <Fact label="Published (server)">
                            <ObservedTime value={snapshot.committedAt} server />
                          </Fact>
                          {!snapshot.packagesAvailable ? (
                            <Fact label="Package rows">
                              No longer retained; the manifest count is not an empty collection.
                            </Fact>
                          ) : null}
                        </dl>
                      ) : (
                        <p>No complete package snapshot has been published.</p>
                      )}
                    </CardContent>
                  </Card>
                </div>
                {data?.stagingSnapshot ? (
                  <Alert>
                    <AlertTitle>Package upload in progress</AlertTitle>
                    <AlertDescription>
                      Snapshot {data.stagingSnapshot.snapshotId}, sequence{" "}
                      {data.stagingSnapshot.sequence.toString()}, is staging. It has not replaced
                      the published inventory.
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
            {resources(() => openForm("resources"))}
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
              <>
                <p className="text-sm text-muted-foreground">
                  Select a lock or wipe action in the preparation form; opening this tab executes
                  nothing.
                </p>
                <DeviceEncryptionPanel key={`encryption:${deviceId}`} deviceId={deviceId} />
                <DeviceActionsPanel key={`actions:${deviceId}`} deviceId={deviceId} />
                {enrollmentRecovery?.(device)}
              </>
            ) : null}
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
          <section
            role="tabpanel"
            id={`${tabId}-history-panel`}
            aria-labelledby={`${tabId}-history-tab`}
            tabIndex={0}
            hidden={activeTab !== "history"}
            className="space-y-4"
          >
            {history}
          </section>
        </>
      ) : null}
    </section>
  );
}
