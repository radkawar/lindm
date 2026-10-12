import { create, toJsonString } from "@bufbuild/protobuf";
import { timestampDate, timestampFromDate } from "@bufbuild/protobuf/wkt";
import { useMutation } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { toast } from "sonner";
import { Search, X } from "lucide-react";
import {
  DeviceCompliance,
  DeviceExportFormat,
  DevicePatchState,
  DeviceFilterSchema,
  type DeviceFilter,
  type ExportDevicesRequest,
  ExportDevicesRequestSchema,
} from "../../../gen/lindm/admin/v1/inventory_management_pb";
import { SuggestionField } from "../../../gen/lindm/admin/v1/suggestions_pb";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import { SuggestionPicker } from "@/components/ui/suggestion-picker";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { RpcError } from "@/components/ui/rpc-error";
import { adminClient } from "@/lib/rpc";
import { AttributeFields, readAttributeInputs } from "./attributes";
import { deviceFilter, deviceSort, type DeviceSearch } from "./search";
import { validateRequest } from "@/lib/validation";

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

const complianceWords: Record<DeviceCompliance, string> = {
  [DeviceCompliance.UNSPECIFIED]: "unknown",
  [DeviceCompliance.UNASSIGNED]: "no profile",
  [DeviceCompliance.COMPLIANT]: "compliant",
  [DeviceCompliance.DRIFT_REMEDIATED]: "drift remediated",
  [DeviceCompliance.STALE]: "not checked recently",
  [DeviceCompliance.UNKNOWN]: "never checked",
  [DeviceCompliance.ATTENTION]: "needs attention",
};

const patchWords: Record<DevicePatchState, string> = {
  [DevicePatchState.UNSPECIFIED]: "unknown",
  [DevicePatchState.UNREPORTED]: "not reported",
  [DevicePatchState.STALE]: "old report",
  [DevicePatchState.SECURITY_PENDING]: "security updates pending",
  [DevicePatchState.RESTART_REQUIRED]: "restart required",
  [DevicePatchState.UP_TO_DATE]: "up to date",
};

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
  const form = useRef<HTMLFormElement>(null);
  function removeFacet(
    change: Partial<
      Pick<DeviceFilter, "namePrefix" | "osId" | "labels" | "compliance" | "patchStates">
    >,
  ) {
    const next = create(DeviceFilterSchema, { ...filter, ...change });
    onSearch({ ...search, filter: toJsonString(DeviceFilterSchema, next), pageToken: "" });
  }
  // Recorded-value choices apply at once, together with whatever else is typed
  // in the form, so choosing an OS never discards an unsubmitted hostname.
  function apply(change: Partial<Pick<DeviceFilter, "osId" | "osVersion" | "labels">> = {}) {
    if (!form.current) return;
    try {
      const data = new FormData(form.current);
      const from = String(data.get("seen-from") ?? "");
      const until = String(data.get("seen-until") ?? "");
      const next = create(DeviceFilterSchema, {
        namePrefix: filter.namePrefix,
        osId: filter.osId,
        osVersion: filter.osVersion,
        labels: filter.labels,
        compliance: filter.compliance,
        patchStates: filter.patchStates,
        attributes: readAttributeInputs(data, attributes),
        lastSeenFrom: from ? timestampFromDate(new Date(`${from}Z`)) : undefined,
        lastSeenUntil: until ? timestampFromDate(new Date(`${until}Z`)) : undefined,
        ...change,
      });
      validateRequest(DeviceFilterSchema, next);
      setError("");
      onSearch({
        ...search,
        filter: toJsonString(DeviceFilterSchema, next),
        hostnameSearch: String(data.get("hostname-search") ?? "").trim(),
        pageToken: "",
      });
    } catch (failure) {
      setError(toRpcFailure(failure).message);
    }
  }
  return (
    <form
      ref={form}
      className="grid gap-3 border bg-card p-4"
      onSubmit={(event) => {
        event.preventDefault();
        apply();
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
              name="hostname-search"
              type="search"
              className="pl-9"
              defaultValue={search.hostnameSearch}
              placeholder="Part of a hostname, any case"
              data-freeform="text searched within hostnames"
            />
          </div>
        </div>
        <div className="min-w-44 flex-1">
          <SuggestionPicker
            label="Operating system"
            field={SuggestionField.OS_ID}
            placeholder="Any operating system"
            note="Operating systems your devices report."
            value={filter.osId}
            onChange={(osId) => apply({ osId, osVersion: "" })}
          />
        </div>
        <div className="min-w-52 flex-1">
          <SuggestionPicker
            label="Add a label"
            field={SuggestionField.DEVICE_LABEL}
            placeholder="Choose a label"
            note="Labels assigned to your devices. Devices must have every chosen label."
            value=""
            onChange={(label) => {
              if (label && !filter.labels.includes(label))
                apply({ labels: [...filter.labels, label] });
            }}
          />
        </div>
        <Button type="submit">Search</Button>
        <Button
          type="button"
          variant="ghost"
          onClick={() => onSearch({ ...search, filter: "", hostnameSearch: "", pageToken: "" })}
        >
          Clear
        </Button>
      </div>
      {search.hostnameSearch ||
      filter.namePrefix ||
      filter.osId ||
      filter.labels.length > 0 ||
      filter.compliance.length > 0 ||
      filter.patchStates.length > 0 ? (
        <div
          className="flex flex-wrap items-center gap-2"
          role="group"
          aria-label="Applied device filters"
        >
          <span className="text-xs text-muted-foreground">Applied</span>
          {search.hostnameSearch ? (
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="h-7 max-w-72 rounded-full bg-muted/40 px-2.5 text-xs"
              aria-label={`Remove hostname filter: ${search.hostnameSearch}`}
              onClick={() => onSearch({ ...search, hostnameSearch: "", pageToken: "" })}
            >
              <span className="truncate">Hostname contains: {search.hostnameSearch}</span>
              <X className="size-3 shrink-0" aria-hidden="true" />
            </Button>
          ) : null}
          {filter.namePrefix ? (
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="h-7 max-w-72 rounded-full bg-muted/40 px-2.5 text-xs"
              aria-label={`Remove hostname prefix filter: ${filter.namePrefix}`}
              onClick={() => removeFacet({ namePrefix: "" })}
            >
              <span className="truncate">Hostname starts with: {filter.namePrefix}</span>
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
          {filter.compliance.length ? (
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="h-auto min-h-7 max-w-full rounded-full bg-muted/40 px-2.5 py-1 text-left text-xs whitespace-normal"
              aria-label="Remove profile state filter"
              onClick={() => removeFacet({ compliance: [] })}
            >
              <span>
                Profile: {filter.compliance.map((state) => complianceWords[state]).join(" or ")}
              </span>
              <X className="size-3 shrink-0" aria-hidden="true" />
            </Button>
          ) : null}
          {filter.patchStates.length ? (
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="h-auto min-h-7 max-w-full rounded-full bg-muted/40 px-2.5 py-1 text-left text-xs whitespace-normal"
              aria-label="Remove update status filter"
              onClick={() => removeFacet({ patchStates: [] })}
            >
              <span>
                Updates: {filter.patchStates.map((state) => patchWords[state]).join(" or ")}
              </span>
              <X className="size-3 shrink-0" aria-hidden="true" />
            </Button>
          ) : null}
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
          <SuggestionPicker
            label="OS version"
            field={SuggestionField.OS_VERSION}
            osId={filter.osId}
            placeholder={filter.osId ? "Any version" : "Choose an operating system first"}
            note="Versions of the chosen operating system that your devices report."
            disabled={!filter.osId}
            value={filter.osVersion}
            onChange={(osVersion) => apply({ osVersion })}
          />
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
        <AttributeFields
          legend="Filter by custom attribute"
          attributes={attributes}
          onChange={setAttributes}
        />
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
      const file = `devices-page-${pages + 1}.${request.format === DeviceExportFormat.CSV ? "csv" : "json"}`;
      const url = URL.createObjectURL(
        new Blob([new Uint8Array(response.content)], { type: response.mediaType }),
      );
      const link = document.createElement("a");
      link.href = url;
      link.download = file;
      link.click();
      URL.revokeObjectURL(url);
      setPageToken(response.nextPageToken);
      setPages((value) => value + 1);
      toast.success(`Downloaded ${file}`, {
        description: response.nextPageToken
          ? "More devices match. Use Download next file."
          : "Export complete.",
      });
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
                sort: deviceSort(search),
                hostnameSearch: search.hostnameSearch ?? "",
                pageSize: search.pageSize,
                pageToken,
              });
              validateRequest(ExportDevicesRequestSchema, request);
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
          {pages === 1 ? "Downloaded 1 file." : `Downloaded ${pages} files.`}{" "}
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
