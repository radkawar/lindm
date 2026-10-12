import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { FilterPanel } from "@/components/ui/filter-panel";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { PickerSlot } from "@/components/ui/search-picker";
import { SelectField } from "@/components/ui/select-field";
import { AUDIT_VIEWS, DEFAULT_AUDIT_VIEW, lastCalendarWeek, type AuditSearch } from "./search";

// One compact bar: the view switch, then actor, device and time range in a
// single row. Below md the view is a select and the scope controls fold behind
// FilterPanel's toggle, so rows stay on the first screen.
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
  const active = [search.actorId, search.deviceId, search.from || search.through].filter(
    Boolean,
  ).length;
  const filtered = active > 0 || search.view !== DEFAULT_AUDIT_VIEW;
  return (
    <section className="grid min-w-0 gap-3 border-y py-3" aria-label="Audit filters">
      <div className="min-w-0">
        <div className="md:hidden">
          <SelectField
            aria-label="Audit view"
            className="data-[size=default]:h-9"
            value={search.view}
            options={AUDIT_VIEWS}
            onValueChange={(view) => {
              const next = AUDIT_VIEWS.find((item) => item.value === view);
              if (next) onChange({ view: next.value });
            }}
          />
        </div>
        <div role="group" aria-label="Audit view" className="hidden flex-wrap gap-1 md:flex">
          {AUDIT_VIEWS.map((view) => (
            <Button
              key={view.value}
              size="sm"
              variant={search.view === view.value ? "default" : "outline"}
              aria-pressed={search.view === view.value}
              onClick={() => onChange({ view: view.value })}
            >
              {view.label}
            </Button>
          ))}
        </div>
      </div>
      <FilterPanel activeCount={active}>
        {/* Top-aligned: a long selected hostname wraps the picker trigger downward
            without pushing the other filters' labels out of line. */}
        <div className="grid gap-3 md:flex md:flex-wrap md:items-start">
          <div className="min-w-0 md:w-56">
            <AccountPicker
              label="Actor"
              value={search.actorId}
              onChange={(actorId) => onChange({ actorId })}
            />
          </div>
          <div className="min-w-0 md:w-56">
            <DevicePicker
              label="Device"
              value={search.deviceId}
              onChange={(deviceId) => onChange({ deviceId })}
            />
          </div>
          <TimeRange key={`${search.from}:${search.through}`} search={search} onChange={onChange} />
          {filtered ? (
            <Button
              className="w-fit md:mt-7"
              variant="ghost"
              onClick={() =>
                onChange({
                  view: DEFAULT_AUDIT_VIEW,
                  actorId: "",
                  deviceId: "",
                  from: "",
                  through: "",
                })
              }
            >
              Clear filters
            </Button>
          ) : null}
        </div>
      </FilterPanel>
    </section>
  );
}

type RangeChoice = "all" | "last-week" | "custom";

const RANGE_OPTIONS = [
  { value: "all", label: "All time" },
  { value: "last-week", label: "Last week, Monday to Sunday (UTC)" },
  { value: "custom", label: "Custom dates (UTC)" },
] as const;

function rangeChoice(search: AuditSearch): RangeChoice {
  if (!search.from && !search.through) return "all";
  const week = lastCalendarWeek(new Date());
  return search.from === week.from && search.through === week.through ? "last-week" : "custom";
}

// The time range is one control: its value is the summary, and custom dates
// appear beside it only when chosen.
function TimeRange({
  search,
  onChange,
}: {
  search: AuditSearch;
  onChange: (next: Partial<AuditSearch>) => void;
}) {
  const [choice, setChoice] = useState<RangeChoice>(rangeChoice(search));
  const [from, setFrom] = useState(search.from);
  const [through, setThrough] = useState(search.through);
  function choose(next: string) {
    if (next === "all") onChange({ from: "", through: "" });
    else if (next === "last-week") onChange(lastCalendarWeek(new Date()));
    else setChoice("custom");
  }
  function apply(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    onChange({ from, through });
  }
  return (
    <div className="grid gap-3 md:contents">
      <div className="grid min-w-0 gap-2 md:w-64">
        <Label htmlFor="audit-range" className="leading-5">
          Time range
        </Label>
        <SelectField
          id="audit-range"
          className="data-[size=default]:h-9"
          value={choice}
          options={RANGE_OPTIONS}
          onValueChange={choose}
        />
      </div>
      {choice === "custom" ? (
        <form className="flex flex-wrap items-end gap-2" onSubmit={apply}>
          <div className="grid gap-2">
            <Label htmlFor="audit-from" className="leading-5">
              From
            </Label>
            <Input
              id="audit-from"
              type="date"
              className="w-40"
              value={from}
              max={through || undefined}
              onChange={(event) => setFrom(event.target.value)}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="audit-through" className="leading-5">
              Through
            </Label>
            <Input
              id="audit-through"
              type="date"
              className="w-40"
              value={through}
              min={from || undefined}
              onChange={(event) => setThrough(event.target.value)}
            />
          </div>
          <Button type="submit" variant="outline">
            Apply dates
          </Button>
        </form>
      ) : null}
    </div>
  );
}
