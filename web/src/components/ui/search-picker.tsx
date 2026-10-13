import { useId, useState, type ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { RpcError } from "@/components/ui/rpc-error";
import { toRpcFailure } from "@/lib/errors";
import {
  Command,
  CommandEmpty,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";

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
  // Shown but not selectable; description must say why.
  disabled?: boolean;
};

// cmdk owns active-descendant navigation, arrow keys, Home/End and Enter selection.
// Search text is never submitted as identity: only a selected server result is used.
// The choices float over the page: opening the picker never moves surrounding content.
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
  placeholder = "Choose…",
  footer,
  children,
}: PickerProps & {
  options: PickerOption[];
  search?: string;
  onSearchChange?: (search: string) => void;
  note?: string;
  // Trigger text when nothing is selected, e.g. "Anyone" for an optional filter.
  placeholder?: string;
  // Rendered inside the open popover below the choices (loading, retry, more choices).
  footer?: ReactNode;
  // Rendered under the trigger whether or not the picker is open.
  children?: ReactNode;
}) {
  const id = useId();
  const [open, setOpen] = useState(false);
  const [chosen, setChosen] = useState<PickerOption>();
  const selected =
    options.find((option) => option.value === value) ??
    (chosen?.value === value ? chosen : undefined);
  return (
    <div className="grid min-w-0 gap-2">
      <span id={`${id}-label`} className="text-sm font-medium">
        {label}
      </span>
      {name ? <input type="hidden" name={name} value={value} /> : null}
      <Popover open={open && !disabled} onOpenChange={setOpen}>
        <PopoverTrigger
          render={
            <Button
              type="button"
              variant="outline"
              className="h-auto min-h-9 justify-start whitespace-normal text-left"
            />
          }
          aria-labelledby={`${id}-label ${id}-value`}
          aria-controls={open ? `${id}-choices` : undefined}
          disabled={disabled}
        >
          <span id={`${id}-value`} className="min-w-0 break-words">
            {selected?.label ?? (value ? "Selected item unavailable" : placeholder)}
          </span>
        </PopoverTrigger>
        <PopoverContent
          aria-labelledby={`${id}-label`}
          onKeyDown={(event) => {
            // Enter selects the active choice; it never submits the surrounding form.
            if (event.key === "Enter") event.preventDefault();
          }}
        >
          <Command id={`${id}-choices`} shouldFilter={!onSearchChange}>
            <CommandInput
              autoFocus
              aria-label={`Search ${label.toLowerCase()}`}
              placeholder="Search by name…"
              value={search}
              onValueChange={onSearchChange}
            />
            <CommandList aria-label={label}>
              <CommandEmpty>No matching options.</CommandEmpty>
              {/* Server-searched text hides the empty choice, as local filtering does,
                  so typing a name and pressing Enter picks the first match. */}
              {onSearchChange && search ? null : (
                <CommandItem
                  value="clear-selection"
                  onSelect={() => {
                    onChange("");
                    setOpen(false);
                  }}
                >
                  {/* An optional filter's placeholder ("Any device") names its empty choice. */}
                  {placeholder === "Choose…" ? "No selection" : placeholder}
                </CommandItem>
              )}
              {options.map((option) => (
                <CommandItem
                  key={option.value}
                  value={option.value}
                  keywords={[option.label, option.description ?? "", ...(option.keywords ?? [])]}
                  data-checked={value === option.value}
                  disabled={option.disabled}
                  onSelect={() => {
                    setChosen(option);
                    onChange(option.value);
                    setOpen(false);
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
            {footer ? <div className="grid gap-2 p-2">{footer}</div> : null}
          </Command>
        </PopoverContent>
      </Popover>
      {children}
    </div>
  );
}

// The footer of a picker whose search runs on the server: loading, a failed read
// with Retry, an empty result that names what was searched, and paging with
// First/More choices. Undefined when there is nothing to say.
export function pickerFooter({
  loading,
  error,
  onRetry,
  empty,
  fetching,
  onFirst,
  onMore,
}: {
  loading: boolean;
  error: unknown;
  onRetry: () => void;
  // Shown once the search has settled with no results; omit otherwise.
  empty?: string;
  fetching: boolean;
  // Present when an earlier page exists, and when another page follows.
  onFirst?: () => void;
  onMore?: () => void;
}): ReactNode {
  if (!loading && !error && !empty && !onFirst && !onMore) return undefined;
  return (
    <>
      {loading ? (
        <p role="status" className="text-xs text-muted-foreground">
          Loading choices…
        </p>
      ) : null}
      {error ? (
        <RpcError failure={toRpcFailure(error)} title="Couldn't load choices">
          <Button type="button" variant="outline" disabled={fetching} onClick={onRetry}>
            Retry choices
          </Button>
        </RpcError>
      ) : null}
      {empty ? <p className="text-xs text-muted-foreground">{empty}</p> : null}
      {onFirst || onMore ? (
        <div className="flex flex-wrap gap-2">
          {onFirst ? (
            <Button type="button" variant="outline" size="sm" disabled={fetching} onClick={onFirst}>
              First choices
            </Button>
          ) : null}
          {onMore ? (
            <Button type="button" variant="outline" size="sm" disabled={fetching} onClick={onMore}>
              More choices
            </Button>
          ) : null}
        </div>
      ) : null}
    </>
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
