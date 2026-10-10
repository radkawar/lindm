import { useState, type ReactNode } from "react";
import {
  CollectionStatus,
  type ApplicationDetails,
  type NativeDetails,
  type ObservedBool,
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
import { CollectionStatusBadge, Fact, ObservedValue } from "./observations";

export function NumberValue({
  field,
  unit = "",
}: {
  field: ObservedUint64 | undefined;
  unit?: string;
}) {
  return field?.status === CollectionStatus.SUCCESS ? (
    <span>
      {field.value.toLocaleString()}
      {unit ? ` ${unit}` : ""}
    </span>
  ) : (
    <CollectionStatusBadge status={field?.status} />
  );
}

function BoolValue({ field }: { field: ObservedBool | undefined }) {
  return field?.status === CollectionStatus.SUCCESS ? (
    <span>{field.value ? "Yes" : "No"}</span>
  ) : (
    <CollectionStatusBadge status={field?.status} />
  );
}

function StringsValue({ field }: { field: ObservedStrings | undefined }) {
  return field?.status === CollectionStatus.SUCCESS ? (
    <span>{field.values.length ? field.values.join(", ") : "None observed"}</span>
  ) : (
    <CollectionStatusBadge status={field?.status} />
  );
}

function NativeRows<T>({
  title,
  status,
  rows,
  headers,
  render,
}: {
  title: string;
  status: CollectionStatus | undefined;
  rows: T[];
  headers: string[];
  render: (row: T) => ReactNode[];
}) {
  const [page, setPage] = useState(0);
  const current = Math.min(page, Math.max(0, Math.ceil(rows.length / 50) - 1));
  return (
    <section className="grid min-w-0 gap-3">
      <h3 className="font-semibold">{title}</h3>
      {status !== CollectionStatus.SUCCESS ? (
        <CollectionStatusBadge status={status} />
      ) : (
        <>
          <p className="text-sm text-muted-foreground">
            {rows.length.toLocaleString()} records observed
          </p>
          {rows.length === 0 ? (
            <p className="text-sm">None observed in this collection.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  {headers.map((header) => (
                    <TableHead key={header}>{header}</TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.slice(current * 50, (current + 1) * 50).map((row, index) => (
                  <TableRow key={current * 50 + index}>
                    {render(row).map((cell, column) => (
                      <TableCell key={headers[column]} className="whitespace-normal break-words">
                        {cell}
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

function Applications({ title, data }: { title: string; data: ApplicationDetails | undefined }) {
  return (
    <NativeRows
      title={title}
      status={data?.status}
      rows={data?.applications ?? []}
      headers={["Name", "Version", "Architecture", "Scope"]}
      render={(row) => [
        row.name,
        <ObservedValue field={row.version} />,
        <ObservedValue field={row.architecture} />,
        <ObservedValue field={row.scope} />,
      ]}
    />
  );
}

export function DeviceNativeDetails({ details }: { details: NativeDetails | undefined }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Native hardware and software observations</CardTitle>
        <CardDescription>
          Collected with the host observation above; its device collection and server receipt times
          apply to every field below. These are observations, not compliance or management support
          claims. Unavailable and denied measurements are never shown as zero or false.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid min-w-0 gap-6">
        {!details ? (
          <p>Native details were not reported by this host observation.</p>
        ) : (
          <>
            <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              <Fact label="CPU model">
                <ObservedValue field={details.cpu?.model} />
              </Fact>
              <Fact label="Logical CPU cores">
                <NumberValue field={details.cpu?.logicalCores} />
              </Fact>
              <Fact label="Physical CPU cores">
                <NumberValue field={details.cpu?.physicalCores} />
              </Fact>
              <Fact label="x86-64 level">
                <ObservedValue field={details.cpu?.x8664Level} />
              </Fact>
              <Fact label="Memory total">
                <NumberValue field={details.memory?.totalBytes} unit="bytes" />
              </Fact>
              <Fact label="Memory available">
                <NumberValue field={details.memory?.availableBytes} unit="bytes" />
              </Fact>
              <Fact label="Swap total">
                <NumberValue field={details.memory?.swapTotalBytes} unit="bytes" />
              </Fact>
              <Fact label="Firmware mode">
                <ObservedValue field={details.firmware?.mode} />
              </Fact>
              <Fact label="Secure Boot">
                <ObservedValue field={details.firmware?.secureBoot} />
              </Fact>
              <Fact label="TPM present">
                <BoolValue field={details.tpm?.present} />
              </Fact>
              <Fact label="TPM version">
                <ObservedValue field={details.tpm?.version} />
              </Fact>
              <Fact label="Chassis">
                <ObservedValue field={details.power?.chassis} />
              </Fact>
              <Fact label="Logged-in users">
                <NumberValue field={details.sessions?.users} />
              </Fact>
              <Fact label="Sessions">
                <NumberValue field={details.sessions?.sessions} />
              </Fact>
              <Fact label="Loaded kernel modules">
                <NumberValue field={details.kernelModuleCount} />
              </Fact>
              <Fact label="Uptime">
                <NumberValue field={details.uptimeSeconds} unit="seconds" />
              </Fact>
              <Fact label="Boot time (Unix seconds, device clock)">
                <NumberValue field={details.bootTimeUnixSeconds} />
              </Fact>
            </dl>
            <section className="grid gap-4">
              <h3 className="font-semibold">Native platform evidence</h3>
              <p className="text-sm text-muted-foreground">
                These are raw native values. Repository IDs do not prove entitlement, support
                coverage or a package module stream.
              </p>
              {!details.platform ? (
                <p className="text-sm">Unknown. Platform evidence was not reported.</p>
              ) : (
                <>
                  <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                    <Fact label="Platform CPE">
                      <ObservedValue field={details.platform.cpe} />
                    </Fact>
                    <Fact label="Release version lock">
                      <ObservedValue field={details.platform.releaseverLock} />
                    </Fact>
                    <Fact label="Repository collection backend">
                      {details.platform.repositories?.backend || "Not reported"}
                    </Fact>
                  </dl>
                  <NativeRows
                    title="Native repository IDs"
                    status={details.platform.repositories?.status}
                    rows={details.platform.repositories?.ids ?? []}
                    headers={["Repository ID"]}
                    render={(id) => [id]}
                  />
                </>
              )}
            </section>
            <NativeRows
              title="Block devices"
              status={details.storage?.status}
              rows={details.storage?.devices ?? []}
              headers={[
                "Name",
                "Type",
                "Parent",
                "Size (bytes)",
                "Filesystem",
                "Mountpoint",
                "Encryption",
              ]}
              render={(row) => [
                row.name,
                <ObservedValue field={row.type} />,
                <ObservedValue field={row.parent} />,
                <NumberValue field={row.sizeBytes} />,
                <ObservedValue field={row.filesystem} />,
                <ObservedValue field={row.mountpoint} />,
                <ObservedValue field={row.encryption} />,
              ]}
            />
            <NativeRows
              title="Network interfaces"
              status={details.network?.status}
              rows={details.network?.interfaces ?? []}
              headers={[
                "Name",
                "MAC",
                "Link",
                "Addresses",
                "IPv4 default route",
                "IPv6 default route",
              ]}
              render={(row) => [
                row.name,
                <ObservedValue field={row.mac} />,
                <ObservedValue field={row.link} />,
                <StringsValue field={row.addresses} />,
                <BoolValue field={row.defaultRouteIpv4} />,
                <BoolValue field={row.defaultRouteIpv6} />,
              ]}
            />
            <NativeRows
              title="Active sessions"
              status={details.sessions?.activeSessions?.status}
              rows={details.sessions?.activeSessions?.sessions ?? []}
              headers={["User", "Class", "Type", "Seat", "Remote"]}
              render={(row) => [
                <ObservedValue field={row.userName} />,
                <ObservedValue field={row.sessionClass} />,
                <ObservedValue field={row.sessionType} />,
                <ObservedValue field={row.seat} />,
                <BoolValue field={row.remote} />,
              ]}
            />
            <NativeRows
              title="Batteries"
              status={details.power?.batteries?.status}
              rows={details.power?.batteries?.items ?? []}
              headers={["Name", "Status", "Capacity"]}
              render={(row) => [
                row.name,
                <ObservedValue field={row.status} />,
                <NumberValue field={row.capacityPercent} unit="%" />,
              ]}
            />
            <NativeRows
              title="Local accounts"
              status={details.localUsers?.status}
              rows={details.localUsers?.users ?? []}
              headers={["UID", "Name", "Shell"]}
              render={(row) => [row.uid.toString(), row.name, row.shell || "No shell recorded"]}
            />
            <section className="grid gap-3">
              <h3 className="font-semibold">Native backend presence</h3>
              <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <Fact label="dpkg">
                  <BoolValue field={details.backends?.dpkg} />
                </Fact>
                <Fact label="RPM">
                  <BoolValue field={details.backends?.rpm} />
                </Fact>
                <Fact label="pacman">
                  <BoolValue field={details.backends?.pacman} />
                </Fact>
                <Fact label="zypper">
                  <BoolValue field={details.backends?.zypper} />
                </Fact>
                <Fact label="rpm-ostree">
                  <BoolValue field={details.backends?.rpmOstree} />
                </Fact>
                <Fact label="Nix">
                  <BoolValue field={details.backends?.nix} />
                </Fact>
                <Fact label="Flatpak">
                  <BoolValue field={details.backends?.flatpak} />
                </Fact>
                <Fact label="Snap">
                  <BoolValue field={details.backends?.snap} />
                </Fact>
              </dl>
            </section>
            <Applications title="Flatpak applications" data={details.flatpak} />
            <Applications title="Snap applications" data={details.snap} />
          </>
        )}
      </CardContent>
    </Card>
  );
}
