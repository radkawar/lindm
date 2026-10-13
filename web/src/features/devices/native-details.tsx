import { useState, type ReactNode } from "react";
import {
  CollectionStatus,
  type ApplicationDetails,
  type NativeDetails,
  type ObservedBool,
  type ObservedString,
  type ObservedUint64,
  type ObservedStrings,
} from "../../../gen/lindm/inventory/v1/observation_pb";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { formatBytes } from "@/lib/bytes";
import { CollectionStatusText, Fact, isOptionalCollectionAbsence } from "./observations";

type NativeField = ObservedString | ObservedBool | ObservedUint64 | ObservedStrings;

type NativeFact = {
  label: string;
  field: NativeField | undefined;
  unit?: string;
  optional?: boolean;
  unavailableLabel?: string;
};

function NativeValue({
  field,
  unit,
  unavailableLabel,
}: Pick<NativeFact, "field" | "unit" | "unavailableLabel">) {
  if (field?.status !== CollectionStatus.SUCCESS) {
    return <CollectionStatusText status={field?.status} unavailableLabel={unavailableLabel} />;
  }
  if ("values" in field) {
    return <span>{field.values.length ? field.values.join(", ") : "None observed"}</span>;
  }
  if (typeof field.value === "boolean") return <span>{field.value ? "Yes" : "No"}</span>;
  if (unit === "bytes" && typeof field.value === "bigint")
    return <span>{formatBytes(field.value)}</span>;
  if (unit === "seconds" && typeof field.value === "bigint")
    return <span>{formatDuration(field.value)}</span>;
  if (unit === "unix-time" && typeof field.value === "bigint")
    return <span>{unixTime.format(new Date(Number(field.value) * 1000))}</span>;
  return (
    <span>
      {typeof field.value === "bigint" ? field.value.toLocaleString() : field.value}
      {unit ? ` ${unit}` : ""}
    </span>
  );
}

const unixTime = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

function formatDuration(seconds: bigint) {
  const total = Number(seconds);
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  if (days > 0) return `${days} ${days === 1 ? "day" : "days"} ${hours} hr`;
  if (hours > 0) return `${hours} hr ${minutes} min`;
  return `${minutes} min`;
}

// lsblk words, as administrators read them.
const blockTypes: Record<string, string> = {
  disk: "Disk",
  part: "Partition",
  crypt: "Unlocked encrypted volume",
  lvm: "LVM volume",
  raid1: "RAID 1",
  rom: "Optical drive",
  loop: "Loop device",
};
const blockEncryption: Record<string, string> = {
  none: "None",
  luks: "LUKS",
  "dm-crypt": "dm-crypt",
  "inherited-dm-crypt": "Inside an encrypted volume",
};

function ObservedWord({
  field,
  words,
}: {
  field: ObservedString | undefined;
  words: Record<string, string>;
}) {
  if (field?.status !== CollectionStatus.SUCCESS)
    return <CollectionStatusText status={field?.status} />;
  return <span>{Object.hasOwn(words, field.value) ? words[field.value] : field.value}</span>;
}

export function NumberValue({ field, unit }: { field: ObservedUint64 | undefined; unit?: string }) {
  return <NativeValue field={field} unit={unit} />;
}

function NativeFacts({
  fields,
  showUnavailable,
}: {
  fields: NativeFact[];
  showUnavailable: boolean;
}) {
  const visible = fields.filter(
    ({ field, optional }) =>
      showUnavailable || !optional || !isOptionalCollectionAbsence(field?.status),
  );
  if (!visible.length) return null;
  return (
    <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
      {visible.map(({ label, ...props }) => (
        <Fact key={label} label={label}>
          <NativeValue {...props} />
        </Fact>
      ))}
    </dl>
  );
}

type NativeColumn<T> = { header: string } & (
  | { field: (row: T) => NativeField | undefined; optional?: boolean; unit?: string }
  | { render: (row: T) => ReactNode }
);

function NativeRows<T>({
  title,
  status,
  rows,
  columns,
  showUnavailable,
  optional = false,
  unavailableLabel,
}: {
  title: string;
  status: CollectionStatus | undefined;
  rows: T[];
  columns: NativeColumn<T>[];
  showUnavailable: boolean;
  optional?: boolean;
  unavailableLabel?: string;
}) {
  const [page, setPage] = useState(0);
  if (optional && !showUnavailable && !rows.length && isOptionalCollectionAbsence(status))
    return null;
  const current = Math.min(page, Math.max(0, Math.ceil(rows.length / 50) - 1));
  // Inspect the entire collection, not just this page, so a failure or known
  // value always keeps its column visible, including successful zero/false.
  const visibleColumns = columns.filter(
    (column) =>
      showUnavailable ||
      !("field" in column) ||
      !column.optional ||
      rows.some((row) => !isOptionalCollectionAbsence(column.field(row)?.status)),
  );
  return (
    <section className="grid min-w-0 gap-3">
      <h3 className="font-semibold">{title}</h3>
      {status !== CollectionStatus.SUCCESS ? (
        <CollectionStatusText status={status} unavailableLabel={unavailableLabel} />
      ) : (
        <>
          {rows.length > 50 ? (
            <p className="text-sm text-muted-foreground">{rows.length.toLocaleString()} observed</p>
          ) : null}
          {rows.length === 0 ? (
            <p className="text-sm">None observed in this collection.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  {visibleColumns.map(({ header }) => (
                    <TableHead key={header}>{header}</TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.slice(current * 50, (current + 1) * 50).map((row, index) => (
                  <TableRow key={current * 50 + index}>
                    {visibleColumns.map((column) => (
                      <TableCell key={column.header} className="whitespace-normal break-words">
                        {"field" in column ? (
                          <NativeValue field={column.field(row)} unit={column.unit} />
                        ) : (
                          column.render(row)
                        )}
                      </TableCell>
                    ))}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
          {rows.length > 50 ? (
            <div className="flex items-center gap-3">
              <Button
                variant="outline"
                disabled={current === 0}
                onClick={() => setPage(current - 1)}
              >
                Previous {title}
              </Button>
              <span className="text-sm">
                Page {current + 1} of {Math.ceil(rows.length / 50)}
              </span>
              <Button
                variant="outline"
                disabled={(current + 1) * 50 >= rows.length}
                onClick={() => setPage(current + 1)}
              >
                Next {title}
              </Button>
            </div>
          ) : null}
        </>
      )}
    </section>
  );
}

function Applications({
  title,
  data,
  backend,
  showUnavailable,
}: {
  title: string;
  data: ApplicationDetails | undefined;
  backend: ObservedBool | undefined;
  showUnavailable: boolean;
}) {
  return (
    <NativeRows
      title={title}
      status={data?.status}
      rows={data?.applications ?? []}
      optional
      showUnavailable={showUnavailable}
      unavailableLabel={
        backend?.status === CollectionStatus.SUCCESS && !backend.value ? "Not installed" : undefined
      }
      columns={[
        { header: "Name", render: (row) => row.name },
        { header: "Version", field: (row) => row.version, optional: true },
        { header: "Architecture", field: (row) => row.architecture, optional: true },
        { header: "Scope", field: (row) => row.scope, optional: true },
      ]}
    />
  );
}

export function DeviceNativeDetails({
  details,
  osId,
}: {
  details: NativeDetails | undefined;
  osId: ObservedString | undefined;
}) {
  const [showUnavailable, setShowUnavailable] = useState(false);
  // Only the successful OS observation from this same host collection can
  // contextualize the DNF-specific fields. CPE is not DNF-specific.
  const dnfUnavailableLabel =
    osId?.status === CollectionStatus.SUCCESS && osId.value === "ubuntu"
      ? "Not applicable on Ubuntu"
      : undefined;
  const platform = details?.platform;
  const showPlatform =
    showUnavailable ||
    [platform?.cpe, platform?.releaseverLock, platform?.releasever, platform?.repositories].some(
      (field) => !isOptionalCollectionAbsence(field?.status),
    ) ||
    !!platform?.repositories?.backend;
  const backendFields: NativeFact[] = [
    { label: "dpkg", field: details?.backends?.dpkg, optional: true },
    { label: "RPM", field: details?.backends?.rpm, optional: true },
    { label: "pacman", field: details?.backends?.pacman, optional: true },
    { label: "zypper", field: details?.backends?.zypper, optional: true },
    { label: "rpm-ostree", field: details?.backends?.rpmOstree, optional: true },
    { label: "Nix", field: details?.backends?.nix, optional: true },
    { label: "Flatpak", field: details?.backends?.flatpak, optional: true },
    { label: "Snap", field: details?.backends?.snap, optional: true },
  ];
  return (
    <Card>
      <CardHeader>
        <CardTitle>Hardware and software</CardTitle>
        <CardDescription>From the device&apos;s latest inventory.</CardDescription>
      </CardHeader>
      <CardContent className="grid min-w-0 gap-6">
        {!details ? (
          <p className="text-muted-foreground">No hardware or software details reported yet.</p>
        ) : (
          <>
            <div className="grid justify-items-start gap-2">
              <Button
                variant="outline"
                aria-pressed={showUnavailable}
                onClick={() => setShowUnavailable(!showUnavailable)}
              >
                Show unavailable fields
              </Button>
              <p className="text-sm text-muted-foreground">
                This view hides empty optional fields.
              </p>
            </div>
            <NativeFacts
              showUnavailable={showUnavailable}
              fields={[
                { label: "CPU model", field: details.cpu?.model },
                { label: "CPU model source", field: details.cpu?.modelSource, optional: true },
                { label: "Logical CPU cores", field: details.cpu?.logicalCores },
                { label: "Physical CPU cores", field: details.cpu?.physicalCores, optional: true },
                { label: "x86-64 level", field: details.cpu?.x8664Level, optional: true },
                { label: "Memory total", field: details.memory?.totalBytes, unit: "bytes" },
                { label: "Memory available", field: details.memory?.availableBytes, unit: "bytes" },
                { label: "Swap total", field: details.memory?.swapTotalBytes, unit: "bytes" },
                { label: "Firmware mode", field: details.firmware?.mode, optional: true },
                { label: "Secure Boot", field: details.firmware?.secureBoot, optional: true },
                { label: "TPM present", field: details.tpm?.present, optional: true },
                { label: "TPM version", field: details.tpm?.version, optional: true },
                { label: "Chassis", field: details.power?.chassis, optional: true },
                { label: "Logged-in users", field: details.sessions?.users },
                { label: "Sessions", field: details.sessions?.sessions },
                {
                  label: "Loaded kernel modules",
                  field: details.kernelModuleCount,
                  optional: true,
                },
                { label: "Uptime", field: details.uptimeSeconds, unit: "seconds" },
                {
                  label: "Booted (device clock)",
                  field: details.bootTimeUnixSeconds,
                  unit: "unix-time",
                },
              ]}
            />
            {showPlatform ? (
              <section className="grid gap-4">
                <h3 className="font-semibold">Platform and repositories</h3>
                <p className="text-sm text-muted-foreground">
                  The device reports these repository settings. The console hides credentials in
                  URLs.
                </p>
                <NativeFacts
                  showUnavailable={showUnavailable}
                  fields={[
                    { label: "Platform CPE", field: platform?.cpe, optional: true },
                    {
                      label: "Effective release version",
                      field: platform?.releasever,
                      optional: true,
                      unavailableLabel: dnfUnavailableLabel,
                    },
                    {
                      label: "Release version lock",
                      field: platform?.releaseverLock,
                      optional: true,
                      unavailableLabel: dnfUnavailableLabel,
                    },
                  ]}
                />
                {platform?.repositories?.backend ? (
                  <dl>
                    <Fact label="Repository collection backend">
                      {platform.repositories.backend}
                    </Fact>
                  </dl>
                ) : showUnavailable ? (
                  <dl>
                    <Fact label="Repository collection backend">
                      <CollectionStatusText status={undefined} />
                    </Fact>
                  </dl>
                ) : null}
                {platform?.repositories?.configurations.length ? (
                  <NativeRows
                    title="Enabled repositories"
                    status={platform.repositories.status}
                    rows={platform.repositories.configurations}
                    columns={[
                      { header: "Repository ID", render: (row) => row.id },
                      {
                        header: "Base URLs",
                        render: (row) => row.baseUrls.join(", ") || "None configured",
                      },
                      { header: "Metalink", render: (row) => row.metalink || "None configured" },
                      {
                        header: "Mirror list",
                        render: (row) => row.mirrorlist || "None configured",
                      },
                      {
                        header: "Package signatures checked",
                        render: (row) => (row.gpgcheck ? "Yes" : "No"),
                      },
                      {
                        header: "Signing keys",
                        render: (row) => row.gpgKeys.join(", ") || "None configured",
                      },
                      {
                        header: "URL data omitted",
                        render: (row) => (row.urlsRedacted ? "Yes" : "No"),
                      },
                    ]}
                    showUnavailable={showUnavailable}
                  />
                ) : (
                  <NativeRows
                    title="Repositories"
                    status={platform?.repositories?.status}
                    rows={platform?.repositories?.ids ?? []}
                    columns={[{ header: "Repository ID", render: (id) => id }]}
                    optional
                    showUnavailable={showUnavailable}
                    unavailableLabel={dnfUnavailableLabel}
                  />
                )}
              </section>
            ) : null}
            <NativeRows
              title="Block devices"
              status={details.storage?.status}
              rows={details.storage?.devices ?? []}
              showUnavailable={showUnavailable}
              columns={[
                {
                  header: "Name",
                  render: (row) => <code className="font-mono">{row.name}</code>,
                },
                {
                  header: "Type",
                  render: (row) => <ObservedWord field={row.type} words={blockTypes} />,
                },
                { header: "Parent", field: (row) => row.parent, optional: true },
                { header: "Size", field: (row) => row.sizeBytes, unit: "bytes" },
                { header: "Filesystem", field: (row) => row.filesystem, optional: true },
                { header: "Mountpoint", field: (row) => row.mountpoint, optional: true },
                {
                  header: "Encryption",
                  render: (row) => (
                    <>
                      <ObservedWord field={row.encryption} words={blockEncryption} />
                      {row.identity?.ephemeralKey?.status === CollectionStatus.SUCCESS &&
                      row.identity.ephemeralKey.value ? (
                        <span className="text-muted-foreground">
                          {" "}
                          · ephemeral random-key swap; destroyed at power-off
                        </span>
                      ) : null}
                    </>
                  ),
                },
              ]}
            />
            <NativeRows
              title="Network interfaces"
              status={details.network?.status}
              rows={details.network?.interfaces ?? []}
              showUnavailable={showUnavailable}
              columns={[
                { header: "Name", render: (row) => row.name },
                { header: "MAC", field: (row) => row.mac, optional: true },
                { header: "Link", field: (row) => row.link },
                { header: "Addresses", field: (row) => row.addresses },
                { header: "IPv4 default route", field: (row) => row.defaultRouteIpv4 },
                { header: "IPv6 default route", field: (row) => row.defaultRouteIpv6 },
              ]}
            />
            <NativeRows
              title="Active sessions"
              status={details.sessions?.activeSessions?.status}
              rows={details.sessions?.activeSessions?.sessions ?? []}
              showUnavailable={showUnavailable}
              columns={[
                { header: "User", field: (row) => row.userName },
                { header: "Class", field: (row) => row.sessionClass },
                { header: "Type", field: (row) => row.sessionType },
                { header: "Seat", field: (row) => row.seat, optional: true },
                { header: "Remote", field: (row) => row.remote },
              ]}
            />
            <NativeRows
              title="Batteries"
              status={details.power?.batteries?.status}
              rows={details.power?.batteries?.items ?? []}
              optional
              showUnavailable={showUnavailable}
              columns={[
                { header: "Name", render: (row) => row.name },
                { header: "Status", field: (row) => row.status },
                {
                  header: "Capacity",
                  field: (row) => row.capacityPercent,
                  unit: "%",
                  optional: true,
                },
              ]}
            />
            <NativeRows
              title="Local accounts"
              status={details.localUsers?.status}
              rows={details.localUsers?.users ?? []}
              showUnavailable={showUnavailable}
              columns={[
                { header: "UID", render: (row) => row.uid.toString() },
                { header: "Name", render: (row) => row.name },
                { header: "Shell", render: (row) => row.shell || "No shell recorded" },
              ]}
            />
            {showUnavailable ||
            backendFields.some((item) => !isOptionalCollectionAbsence(item.field?.status)) ? (
              <section className="grid gap-3">
                <h3 className="font-semibold">App platforms</h3>
                <NativeFacts showUnavailable={showUnavailable} fields={backendFields} />
              </section>
            ) : null}
            <Applications
              title="Flatpak applications"
              data={details.flatpak}
              backend={details.backends?.flatpak}
              showUnavailable={showUnavailable}
            />
            <Applications
              title="Snap applications"
              data={details.snap}
              backend={details.backends?.snap}
              showUnavailable={showUnavailable}
            />
          </>
        )}
      </CardContent>
    </Card>
  );
}
