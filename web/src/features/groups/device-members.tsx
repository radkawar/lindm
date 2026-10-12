import { useId, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { XIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { PickerSlot } from "@/components/ui/search-picker";

export type DeviceLabelSlot = (props: { value: string }) => ReactNode;

// Chips beyond this are behind "Show all", so a large group stays one screen.
const VISIBLE_CHIPS = 24;

// One device multi-select: the searchable device picker adds a device, chips
// show the chosen devices by hostname and OS and remove them with the mouse or
// Backspace/Delete. Only selected picker results are ever added.
export function DeviceMembersField({
  label,
  values,
  onChange,
  picker: Picker,
  deviceLabel: DeviceLabel,
  disabled,
}: {
  label: string;
  values: string[];
  onChange: (values: string[]) => void;
  picker: PickerSlot;
  deviceLabel: DeviceLabelSlot;
  disabled?: boolean;
}) {
  const id = useId();
  const [showAll, setShowAll] = useState(false);
  const chips = useRef(new Map<string, HTMLButtonElement>());
  const addArea = useRef<HTMLDivElement>(null);
  const visible = showAll ? values : values.slice(0, VISIBLE_CHIPS);

  function remove(index: number) {
    const next = values.filter((_, i) => i !== index);
    onChange(next);
    // Keep the keyboard on the chip list: the next chip, else the previous,
    // else the picker that adds devices.
    const focus = next[index] ?? next[index - 1];
    requestAnimationFrame(() => {
      const target = focus ? chips.current.get(focus) : undefined;
      if (target) target.focus();
      else addArea.current?.querySelector<HTMLElement>("button")?.focus();
    });
  }
  function onKeyDown(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    if (event.key === "Backspace" || event.key === "Delete") {
      event.preventDefault();
      remove(index);
    }
  }

  return (
    <fieldset className="grid min-w-0 gap-2" disabled={disabled}>
      <legend className="mb-1 text-sm font-medium">{label}</legend>
      {values.length === 0 ? (
        <p className="text-sm text-muted-foreground">No devices yet. Add one below.</p>
      ) : (
        <ul aria-label={`Selected ${label.toLowerCase()}`} className="flex min-w-0 flex-wrap gap-2">
          {visible.map((value, index) => (
            <li
              key={value}
              className="inline-flex min-w-0 max-w-full items-center gap-1 border bg-muted/40 py-0.5 pr-0.5 pl-2 text-sm"
            >
              <span id={`${id}-chip-${index}`} className="min-w-0">
                <DeviceLabel value={value} />
              </span>
              <Button
                ref={(element) => {
                  if (element) chips.current.set(value, element);
                  else chips.current.delete(value);
                }}
                type="button"
                variant="ghost"
                size="icon-xs"
                disabled={disabled}
                aria-labelledby={`${id}-remove ${id}-chip-${index}`}
                onKeyDown={(event) => onKeyDown(event, index)}
                onClick={() => remove(index)}
              >
                <XIcon aria-hidden="true" />
              </Button>
            </li>
          ))}
        </ul>
      )}
      <span id={`${id}-remove`} className="sr-only">
        Remove
      </span>
      {values.length > VISIBLE_CHIPS ? (
        <Button
          type="button"
          variant="link"
          className="h-auto w-fit p-0"
          aria-expanded={showAll}
          onClick={() => setShowAll(!showAll)}
        >
          {showAll ? "Show fewer" : `Show all ${values.length} devices`}
        </Button>
      ) : null}
      <div ref={addArea} className="min-w-0">
        <Picker
          label="Add a device"
          value=""
          disabled={disabled}
          onChange={(device) => {
            if (device && !values.includes(device)) onChange([...values, device]);
          }}
        />
      </div>
    </fieldset>
  );
}
