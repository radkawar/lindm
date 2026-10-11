import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { PickerSlot } from "@/components/ui/search-picker";
import { AUDIT_VIEWS, auditRangeLabel, lastCalendarWeek, type AuditSearch } from "./search";

export function AuditFilters({
  search,
  onChange,
  accountPicker: AccountPicker,
  devicePicker: DevicePicker,
}: {
  search: AuditSearch;
  onChange: (next: Partial<AuditSearch>) => void;
  accountPicker: PickerSlot;
  devicePicker: PickerSlot;
}) {
  return (
    <section className="grid gap-4 border-y py-4" aria-label="Audit filters">
      <div className="grid gap-2">
        <h2 className="text-sm font-medium">Quick views</h2>
        <div className="flex flex-wrap gap-2">
          {AUDIT_VIEWS.map((view) => (
            <Button
              key={view.value}
              variant={search.view === view.value ? "default" : "outline"}
              aria-pressed={search.view === view.value}
              onClick={() => onChange({ view: view.value })}
            >
              {view.label}
            </Button>
          ))}
        </div>
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        <div className="grid content-start gap-1">
          <AccountPicker
            label="Actor account"
            value={search.actorId}
            onChange={(actorId) => onChange({ actorId })}
          />
          {!search.actorId ? (
            <p className="text-xs text-muted-foreground">All actors, including the system</p>
          ) : null}
        </div>
        <div className="grid content-start gap-1">
          <DevicePicker
            label="Target device"
            value={search.deviceId}
            onChange={(deviceId) => onChange({ deviceId })}
          />
          {!search.deviceId ? (
            <p className="text-xs text-muted-foreground">All devices and events without a device</p>
          ) : null}
        </div>
      </div>
      <div className="grid gap-2">
        <h2 className="text-sm font-medium">Time range</h2>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" onClick={() => onChange(lastCalendarWeek(new Date()))}>
            Last week
          </Button>
          <Button variant="outline" onClick={() => onChange({ from: "", through: "" })}>
            All time
          </Button>
        </div>
        <p className="text-xs text-muted-foreground">
          Last week is the previous Monday through Sunday in UTC, saved as fixed dates in this link.
        </p>
        <DateRange key={`${search.from}:${search.through}`} search={search} onChange={onChange} />
        <p className="text-sm" role="status">
          {auditRangeLabel(search)}
        </p>
      </div>
      <Button
        className="w-fit"
        variant="ghost"
        onClick={() => onChange({ view: "all", actorId: "", deviceId: "", from: "", through: "" })}
      >
        Clear filters
      </Button>
    </section>
  );
}

function DateRange({
  search,
  onChange,
}: {
  search: AuditSearch;
  onChange: (next: Partial<AuditSearch>) => void;
}) {
  const [from, setFrom] = useState(search.from);
  const [through, setThrough] = useState(search.through);
  function apply(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    onChange({ from, through });
  }
  return (
    <form className="flex flex-wrap items-end gap-3" onSubmit={apply}>
      <div className="grid gap-1">
        <Label htmlFor="audit-from">From (UTC)</Label>
        <Input
          id="audit-from"
          type="date"
          value={from}
          max={through || undefined}
          onChange={(event) => setFrom(event.target.value)}
        />
      </div>
      <div className="grid gap-1">
        <Label htmlFor="audit-through">Through (UTC)</Label>
        <Input
          id="audit-through"
          type="date"
          value={through}
          min={from || undefined}
          onChange={(event) => setThrough(event.target.value)}
        />
      </div>
      <Button type="submit" variant="outline">
        Apply dates
      </Button>
    </form>
  );
}
