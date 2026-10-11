import { useId, useRef, useState, type ReactNode } from "react";
import { Button } from "@/components/ui/button";
import {
  Command,
  CommandEmpty,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";

export type PickerProps = {
  label: string;
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
  name?: string;
};
export type PickerSlot = (props: PickerProps) => ReactNode;
export type PickerOption = {
  value: string;
  label: string;
  description?: string;
  keywords?: string[];
};

// cmdk owns active-descendant navigation, arrow keys, Home/End and Enter selection.
// Search text is never submitted as identity: only a selected server result is used.
export function SearchPicker({
  label,
  value,
  onChange,
  disabled,
  name,
  options,
  search,
  onSearchChange,
  note,
  children,
}: PickerProps & {
  options: PickerOption[];
  search?: string;
  onSearchChange?: (search: string) => void;
  note?: string;
  children?: ReactNode;
}) {
  const id = useId();
  const [open, setOpen] = useState(false);
  const trigger = useRef<HTMLButtonElement>(null);
  const [chosen, setChosen] = useState<PickerOption>();
  const selected =
    options.find((option) => option.value === value) ??
    (chosen?.value === value ? chosen : undefined);
  function close() {
    setOpen(false);
    trigger.current?.focus();
  }
  return (
    <div
      className="grid min-w-0 gap-2"
      onKeyDown={(event) => {
        if (open && event.key === "Enter") event.preventDefault();
        if (open && event.key === "Escape") {
          event.preventDefault();
          event.stopPropagation();
          close();
        }
      }}
    >
      <span id={`${id}-label`} className="text-sm font-medium">
        {label}
      </span>
      {name ? <input type="hidden" name={name} value={value} /> : null}
      <Button
        ref={trigger}
        type="button"
        variant="outline"
        className="h-auto min-h-9 justify-start whitespace-normal text-left"
        aria-labelledby={`${id}-label ${id}-value`}
        aria-expanded={open}
        aria-controls={open ? `${id}-choices` : undefined}
        disabled={disabled}
        onClick={() => setOpen(!open)}
      >
        <span id={`${id}-value`}>
          {selected?.label ?? (value ? "Selected item unavailable" : "Choose…")}
        </span>
      </Button>
      {open && !disabled ? (
        <Command id={`${id}-choices`} className="border" shouldFilter={!onSearchChange}>
          <CommandInput
            autoFocus
            aria-label={`Search ${label.toLowerCase()}`}
            placeholder="Search by name…"
            value={search}
            onValueChange={onSearchChange}
          />
          <CommandList aria-label={label}>
            <CommandEmpty>No matching options.</CommandEmpty>
            <CommandItem
              value="clear-selection"
              onSelect={() => {
                onChange("");
                close();
              }}
            >
              No selection
            </CommandItem>
            {options.map((option) => (
              <CommandItem
                key={option.value}
                value={option.value}
                keywords={[option.label, option.description ?? "", ...(option.keywords ?? [])]}
                data-checked={value === option.value}
                onSelect={() => {
                  setChosen(option);
                  onChange(option.value);
                  close();
                }}
              >
                <span className="grid min-w-0 gap-0.5">
                  <span className="break-words">{option.label}</span>
                  {option.description ? (
                    <span className="text-xs text-muted-foreground">{option.description}</span>
                  ) : null}
                </span>
              </CommandItem>
            ))}
          </CommandList>
          {note ? <p className="p-2 text-xs text-muted-foreground">{note}</p> : null}
        </Command>
      ) : null}
      {children}
    </div>
  );
}

export function MultiPicker({
  label,
  values,
  onChange,
  picker,
  disabled,
}: {
  label: string;
  values: string[];
  onChange: (values: string[]) => void;
  picker: PickerSlot;
  disabled?: boolean;
}) {
  const Picker = picker;
  return (
    <fieldset className="grid gap-3" disabled={disabled}>
      <legend className="text-sm font-medium">{label}</legend>
      {values.map((value, index) => (
        <div className="grid gap-2" key={index}>
          <Picker
            label={`${label} ${index + 1}`}
            value={value}
            disabled={disabled}
            onChange={(next) => onChange(values.map((item, i) => (i === index ? next : item)))}
          />
          <Button
            type="button"
            variant="outline"
            disabled={disabled}
            onClick={() => onChange(values.filter((_, i) => i !== index))}
          >
            Remove selection {index + 1}
          </Button>
        </div>
      ))}
      <Button
        type="button"
        variant="outline"
        disabled={disabled}
        onClick={() => onChange([...values, ""])}
      >
        Add selection
      </Button>
    </fieldset>
  );
}
