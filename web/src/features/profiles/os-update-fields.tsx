import type { JsonObject } from "@bufbuild/protobuf";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import { object } from "./resource-draft";

type Props = {
  value: JsonObject;
  onChange: (value: JsonObject) => void;
  id: string;
  disabled: boolean;
};

const days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
const defaultWindow: JsonObject = {
  timeZone: "UTC",
  weekdays: ["WEEKDAY_SUNDAY"],
  localStartMinute: 240,
  durationMinutes: 120,
};

function WindowFields({ value, onChange, id, disabled }: Props) {
  const minute = Number(value.localStartMinute ?? 0);
  const selected = Array.isArray(value.weekdays) ? value.weekdays : [];
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      <div className="grid gap-1.5">
        <Label htmlFor={`${id}-zone`}>Time zone</Label>
        <Input
          id={`${id}-zone`}
          disabled={disabled}
          value={String(value.timeZone ?? "")}
          onChange={(event) => onChange({ ...value, timeZone: event.target.value })}
        />
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor={`${id}-start`}>Start time</Label>
        <Input
          id={`${id}-start`}
          type="time"
          disabled={disabled}
          value={`${String(Math.floor(minute / 60)).padStart(2, "0")}:${String(minute % 60).padStart(2, "0")}`}
          onChange={(event) => {
            const [hour, minutes] = event.target.value.split(":").map(Number);
            if (hour !== undefined && minutes !== undefined)
              onChange({ ...value, localStartMinute: hour * 60 + minutes });
          }}
        />
      </div>
      <fieldset className="grid gap-2 sm:col-span-2" disabled={disabled}>
        <legend className="mb-2 text-sm font-medium">Days</legend>
        <div className="flex flex-wrap gap-3">
          {days.map((day, index) => {
            const name = `WEEKDAY_${day.toUpperCase()}`;
            return (
              <label key={day} className="flex items-center gap-1.5 text-sm">
                <input
                  type="checkbox"
                  className="accent-primary"
                  checked={selected.includes(name) || selected.includes(index + 1)}
                  onChange={(event) => {
                    const remaining = selected.filter(
                      (entry) => entry !== name && entry !== index + 1,
                    );
                    onChange({
                      ...value,
                      weekdays: event.target.checked ? [...remaining, name] : remaining,
                    });
                  }}
                />
                {day}
              </label>
            );
          })}
        </div>
      </fieldset>
      <div className="grid gap-1.5">
        <Label htmlFor={`${id}-duration`}>Window length (minutes)</Label>
        <Input
          id={`${id}-duration`}
          type="number"
          disabled={disabled}
          value={Number(value.durationMinutes ?? 120)}
          onChange={(event) => onChange({ ...value, durationMinutes: Number(event.target.value) })}
        />
      </div>
    </div>
  );
}

export function OSUpdateFields({ value, onChange, id, disabled }: Props) {
  const reboot = object(value.rebootPolicy);
  const scheduled = reboot.mode === "OS_UPDATE_REBOOT_MODE_SCHEDULED" || reboot.mode === 2;
  const changeReboot = (next: JsonObject) => onChange({ ...value, rebootPolicy: next });
  return (
    <div className="grid gap-5">
      <details className="text-sm">
        <summary className="cursor-pointer font-medium">Timing and prerequisites</summary>
        <p className="mt-2 text-muted-foreground">
          Devices need their native automatic-update tools and signed repositories. Windows use the
          selected time zone. A start skipped by daylight saving does not open that day; a repeated
          start opens only once.
        </p>
      </details>
      <section className="grid gap-3">
        <h2 className="text-base font-semibold">Install updates</h2>
        <Label htmlFor={`${id}-selection`}>Updates to install</Label>
        <SelectField
          id={`${id}-selection`}
          disabled={disabled}
          value={
            value.selection === 2
              ? "UPDATE_SELECTION_ALL"
              : value.selection === 1
                ? "UPDATE_SELECTION_SECURITY"
                : String(value.selection ?? "UPDATE_SELECTION_SECURITY")
          }
          options={[
            { value: "UPDATE_SELECTION_SECURITY", label: "Security updates" },
            { value: "UPDATE_SELECTION_ALL", label: "All updates" },
          ]}
          onValueChange={(selection) => onChange({ ...value, selection })}
        />
        <WindowFields
          value={object(value.maintenance)}
          onChange={(maintenance) => onChange({ ...value, maintenance })}
          id={`${id}-install`}
          disabled={disabled}
        />
        <p className="text-sm text-muted-foreground">
          Updates may start in this window and continue until their transaction finishes.
        </p>
        <Label htmlFor={`${id}-update-delay`}>Wait before installing new updates (days)</Label>
        <Input
          id={`${id}-update-delay`}
          type="number"
          disabled={disabled}
          value={Number(value.deferralDays ?? 0)}
          onChange={(event) => onChange({ ...value, deferralDays: Number(event.target.value) })}
        />
      </section>
      <section className="grid gap-3 border-t pt-4">
        <h2 className="text-base font-semibold">Restart devices</h2>
        <Label htmlFor={`${id}-restart`}>After updates need a restart</Label>
        <SelectField
          id={`${id}-restart`}
          disabled={disabled}
          value={scheduled ? "scheduled" : "never"}
          options={[
            { value: "never", label: "Let the employee restart" },
            { value: "scheduled", label: "Schedule a restart" },
          ]}
          onValueChange={(mode) =>
            changeReboot(
              mode === "never"
                ? { mode: "OS_UPDATE_REBOOT_MODE_NEVER" }
                : { mode: "OS_UPDATE_REBOOT_MODE_SCHEDULED", maxDelayMinutes: 60 },
            )
          }
        />
        {scheduled && (
          <>
            <Label htmlFor={`${id}-deadline`}>Restart deadline after updates (minutes)</Label>
            <Input
              id={`${id}-deadline`}
              type="number"
              disabled={disabled}
              value={Number(reboot.maxDelayMinutes ?? 60)}
              onChange={(event) =>
                changeReboot({ ...reboot, maxDelayMinutes: Number(event.target.value) })
              }
            />
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                disabled={disabled}
                checked={reboot.rebootWindow !== undefined}
                onChange={(event) => {
                  const next = { ...reboot };
                  if (event.target.checked)
                    next.rebootWindow = {
                      ...defaultWindow,
                      timeZone: object(value.maintenance).timeZone ?? "UTC",
                    };
                  else delete next.rebootWindow;
                  changeReboot(next);
                }}
              />
              Use a separate restart window
            </label>
            {reboot.rebootWindow !== undefined && (
              <WindowFields
                value={object(reboot.rebootWindow)}
                onChange={(rebootWindow) => changeReboot({ ...reboot, rebootWindow })}
                id={`${id}-reboot`}
                disabled={disabled}
              />
            )}
            <p className="text-sm text-muted-foreground">
              If no restart time fits before the deadline, no restart is scheduled.
            </p>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                disabled={disabled}
                checked={reboot.employeeDeferral !== undefined}
                onChange={(event) => {
                  const next = { ...reboot };
                  if (event.target.checked)
                    next.employeeDeferral = { maxDeferrals: 2, delayMinutes: 15 };
                  else delete next.employeeDeferral;
                  changeReboot(next);
                }}
              />
              Allow employees to defer a restart
            </label>
            {reboot.employeeDeferral !== undefined && (
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="grid gap-1.5">
                  <Label htmlFor={`${id}-count`}>Maximum deferrals</Label>
                  <Input
                    id={`${id}-count`}
                    type="number"
                    disabled={disabled}
                    value={Number(object(reboot.employeeDeferral).maxDeferrals ?? 2)}
                    onChange={(event) =>
                      changeReboot({
                        ...reboot,
                        employeeDeferral: {
                          ...object(reboot.employeeDeferral),
                          maxDeferrals: Number(event.target.value),
                        },
                      })
                    }
                  />
                </div>
                <div className="grid gap-1.5">
                  <Label htmlFor={`${id}-delay`}>Defer each restart by (minutes)</Label>
                  <Input
                    id={`${id}-delay`}
                    type="number"
                    disabled={disabled}
                    value={Number(object(reboot.employeeDeferral).delayMinutes ?? 15)}
                    onChange={(event) =>
                      changeReboot({
                        ...reboot,
                        employeeDeferral: {
                          ...object(reboot.employeeDeferral),
                          delayMinutes: Number(event.target.value),
                        },
                      })
                    }
                  />
                </div>
                <p className="text-sm text-muted-foreground sm:col-span-2">
                  Deferrals move to the next allowed time, never beyond the deadline.
                </p>
              </div>
            )}
            <Label htmlFor={`${id}-notice`}>Message for employees</Label>
            <Input
              id={`${id}-notice`}
              disabled={disabled}
              value={String(reboot.notice ?? "")}
              onChange={(event) => changeReboot({ ...reboot, notice: event.target.value })}
            />
          </>
        )}
      </section>
    </div>
  );
}
