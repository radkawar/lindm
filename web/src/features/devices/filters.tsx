import { create, toJsonString } from "@bufbuild/protobuf";
import { timestampDate, timestampFromDate } from "@bufbuild/protobuf/wkt";
import { useMutation } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { Search, X } from "lucide-react";
import {
  DeviceExportFormat,
  DeviceFilterSchema,
  type DeviceFilter,
  type ExportDevicesRequest,
  ExportDevicesRequestSchema,
} from "../../../gen/lindm/admin/v1/inventory_management_pb";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { RpcError } from "@/components/ui/rpc-error";
import { adminClient } from "@/lib/rpc";
import { AttributeFields, readAttributeInputs } from "./attributes";
import { deviceFilter, type DeviceSearch } from "./search";
import { validateInventory } from "./validation";

export function DeviceFilters({
  search,
  onSearch,
}: {
  search: DeviceSearch;
  onSearch: (search: DeviceSearch) => void;
}) {
  let filter: DeviceFilter;
  try {
    filter = deviceFilter(search);
  } catch (error) {
    return (
      <Alert variant="destructive">
        <AlertDescription>
          Invalid inventory filter: {toRpcFailure(error).message}
          <Button
            variant="outline"
            onClick={() => onSearch({ ...search, filter: "", pageToken: "" })}
          >
            Clear filters
          </Button>
        </AlertDescription>
      </Alert>
    );
  }
  return (
    <FilterForm key={search.filter ?? ""} filter={filter} search={search} onSearch={onSearch} />
  );
}

function FilterForm({
  filter,
  search,
  onSearch,
}: {
  filter: DeviceFilter;
  search: DeviceSearch;
  onSearch: (search: DeviceSearch) => void;
}) {
  const [attributes, setAttributes] = useState(filter.attributes);
  const [error, setError] = useState("");
  function removeFacet(change: Partial<Pick<DeviceFilter, "namePrefix" | "osId" | "labels">>) {
    const next = create(DeviceFilterSchema, { ...filter, ...change });
    onSearch({ ...search, filter: toJsonString(DeviceFilterSchema, next), pageToken: "" });
  }
  return (
    <form
      className="grid gap-3 border bg-card p-4"
      onSubmit={(event) => {
        event.preventDefault();
        try {
          const data = new FormData(event.currentTarget);
          const from = String(data.get("seen-from") ?? "");
          const until = String(data.get("seen-until") ?? "");
          const next = create(DeviceFilterSchema, {
            namePrefix: String(data.get("name-prefix") ?? ""),
            osId: String(data.get("os") ?? "").trim(),
            osVersion: String(data.get("version") ?? "").trim(),
            labels: String(data.get("labels") ?? "")
              .split(/\s+/)
              .filter(Boolean),
            attributes: readAttributeInputs(data, attributes),
            lastSeenFrom: from ? timestampFromDate(new Date(`${from}Z`)) : undefined,
            lastSeenUntil: until ? timestampFromDate(new Date(`${until}Z`)) : undefined,
          });
          validateInventory(DeviceFilterSchema, next);
          setError("");
          onSearch({ ...search, filter: toJsonString(DeviceFilterSchema, next), pageToken: "" });
        } catch (failure) {
          setError(toRpcFailure(failure).message);
        }
      }}
    >
      <div className="flex flex-wrap items-end gap-3">
        <div className="grid min-w-56 flex-1 gap-1.5">
          <Label htmlFor="filter-name">Search devices</Label>
          <div className="relative">
            <Search
              className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
              aria-hidden="true"
            />
            <Input
              id="filter-name"
              name="name-prefix"
              type="search"
              className="pl-9"
              defaultValue={filter.namePrefix}
              placeholder="Hostname starts with…"
            />
          </div>
        </div>
        <div className="grid min-w-44 flex-1 gap-1.5">
          <Label htmlFor="filter-os">Operating system</Label>
          <Input id="filter-os" name="os" defaultValue={filter.osId} placeholder="e.g. ubuntu" />
        </div>
        <div className="grid min-w-52 flex-1 gap-1.5">
          <Label htmlFor="filter-labels">Labels</Label>
          <Input
            id="filter-labels"
            name="labels"
            defaultValue={filter.labels.join(" ")}
            placeholder="Space-separated"
          />
        </div>
        <Button type="submit">Search</Button>
        <Button
          type="button"
          variant="ghost"
          onClick={() => onSearch({ ...search, filter: "", pageToken: "" })}
        >
          Clear
        </Button>
      </div>
      {filter.namePrefix || filter.osId || filter.labels.length > 0 ? (
        <div
          className="flex flex-wrap items-center gap-2"
          role="group"
          aria-label="Applied device filters"
        >
          <span className="text-xs text-muted-foreground">Applied</span>
          {filter.namePrefix ? (
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="h-7 max-w-72 rounded-full bg-muted/40 px-2.5 text-xs"
              aria-label={`Remove hostname prefix filter: ${filter.namePrefix}`}
              onClick={() => removeFacet({ namePrefix: "" })}
            >
              <span className="truncate">Name: {filter.namePrefix}</span>
              <X className="size-3 shrink-0" aria-hidden="true" />
            </Button>
          ) : null}
          {filter.osId ? (
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="h-7 max-w-72 rounded-full bg-muted/40 px-2.5 text-xs"
              aria-label={`Remove operating system filter: ${filter.osId}`}
              onClick={() => removeFacet({ osId: "" })}
            >
              <span className="truncate">OS: {filter.osId}</span>
              <X className="size-3 shrink-0" aria-hidden="true" />
            </Button>
          ) : null}
          {filter.labels.map((label) => (
            <Button
              key={label}
              type="button"
              variant="outline"
              size="sm"
              className="h-7 max-w-72 rounded-full bg-muted/40 px-2.5 text-xs"
              aria-label={`Remove label filter: ${label}`}
              onClick={() =>
                removeFacet({ labels: filter.labels.filter((value) => value !== label) })
              }
            >
              <span className="truncate">Label: {label}</span>
              <X className="size-3 shrink-0" aria-hidden="true" />
            </Button>
          ))}
        </div>
      ) : null}
      <details
        open={Boolean(
          filter.osVersion ||
          filter.lastSeenFrom ||
          filter.lastSeenUntil ||
          filter.attributes.length,
        )}
      >
        <summary className="w-fit cursor-pointer text-xs font-medium text-muted-foreground">
          More filters
        </summary>
        <p className="mt-3 text-xs text-muted-foreground">
          Hostname matches the start of the name (case-sensitive). Other fields must match exactly.
          Times are UTC.
        </p>
        <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <div className="grid gap-1.5">
            <Label htmlFor="filter-version">OS version</Label>
            <Input
              id="filter-version"
              name="version"
              defaultValue={filter.osVersion}
              placeholder="All versions"
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="filter-from">Last seen from (UTC)</Label>
            <Input
              id="filter-from"
              name="seen-from"
              type="datetime-local"
              step="1"
              defaultValue={
                filter.lastSeenFrom
                  ? timestampDate(filter.lastSeenFrom).toISOString().slice(0, 19)
                  : ""
              }
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="filter-until">Last seen until (UTC)</Label>
            <Input
              id="filter-until"
              name="seen-until"
              type="datetime-local"
              step="1"
              defaultValue={
                filter.lastSeenUntil
                  ? timestampDate(filter.lastSeenUntil).toISOString().slice(0, 19)
                  : ""
              }
            />
          </div>
        </div>
        <AttributeFields attributes={attributes} onChange={setAttributes} />
      </details>
      {error ? (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      ) : null}
    </form>
  );
}

export function DeviceExport({ search }: { search: DeviceSearch }) {
  const lifetime = useAuthLifetime();
  const [format, setFormat] = useState(DeviceExportFormat.CSV);
  const [pageToken, setPageToken] = useState("");
  const [pages, setPages] = useState(0);
  const inFlight = useRef(false);
  const download = useMutation({
    retry: false,
    meta: { authGeneration: lifetime.generation },
    mutationFn: async (request: ExportDevicesRequest) => {
      const response = await adminClient.exportDevices(request, { signal: lifetime.signal });
      lifetime.signal.throwIfAborted();
      return response;
    },
    onSuccess: (response, request) => {
      const url = URL.createObjectURL(
        new Blob([new Uint8Array(response.content)], { type: response.mediaType }),
      );
      const link = document.createElement("a");
      link.href = url;
      link.download = `devices-page-${pages + 1}.${request.format === DeviceExportFormat.CSV ? "csv" : "json"}`;
      link.click();
      URL.revokeObjectURL(url);
      setPageToken(response.nextPageToken);
      setPages((value) => value + 1);
    },
    onSettled: () => {
      inFlight.current = false;
    },
  });
  const failure = download.error ? toRpcFailure(download.error) : null;
  const [inputError, setInputError] = useState("");
  return (
    <section className="grid gap-2 rounded-lg border p-4">
      <h2 className="font-semibold">Export devices</h2>
      <p className="text-sm text-muted-foreground">
        Exports devices matching the current filters, up to {search.pageSize} per file.
      </p>
      <div className="flex flex-wrap items-center gap-2">
        <Label htmlFor="export-format">Format</Label>
        <SelectField
          id="export-format"
          value={format}
          disabled={download.isPending || pages > 0}
          onValueChange={(value) => setFormat(Number(value) as DeviceExportFormat)}
          options={[
            { value: DeviceExportFormat.CSV, label: "CSV" },
            { value: DeviceExportFormat.JSON, label: "JSON" },
          ]}
        />
        <Button
          disabled={download.isPending || (pages > 0 && !pageToken)}
          onClick={() => {
            if (inFlight.current) return;
            try {
              const request = create(ExportDevicesRequestSchema, {
                format,
                filter: deviceFilter(search),
                pageSize: search.pageSize,
                pageToken,
              });
              validateInventory(ExportDevicesRequestSchema, request);
              inFlight.current = true;
              setInputError("");
              download.mutate(request);
            } catch (error) {
              setInputError(toRpcFailure(error).message);
            }
          }}
        >
          {download.isPending ? "Exporting…" : pages ? "Download next file" : "Download"}
        </Button>
        <Button
          variant="outline"
          disabled={download.isPending}
          onClick={() => {
            setPages(0);
            setPageToken("");
            download.reset();
          }}
        >
          Start over
        </Button>
      </div>
      {pages ? (
        <p role="status" className="text-sm">
          Downloaded {pages} file(s).{" "}
          {pageToken ? "More devices are available." : "Export complete."}
        </p>
      ) : null}
      {failure ? <RpcError failure={failure} /> : null}
      {inputError ? (
        <p role="alert" className="text-sm text-destructive">
          {inputError}
        </p>
      ) : null}
    </section>
  );
}
