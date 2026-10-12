import type { ReactNode } from "react";
import { cn } from "cn";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "./select";

export function SelectField({
  id,
  name,
  value,
  defaultValue,
  disabled,
  required,
  className,
  options,
  placeholder,
  onValueChange,
  "aria-label": ariaLabel,
  "aria-describedby": ariaDescribedBy,
}: {
  id?: string;
  name?: string;
  value?: string | number;
  defaultValue?: string | number;
  disabled?: boolean;
  required?: boolean;
  className?: string;
  "aria-label"?: string;
  "aria-describedby"?: string;
  options: readonly { value: string | number; label: ReactNode; disabled?: boolean }[];
  // Shown while the controlled value is "", which then means nothing chosen yet.
  placeholder?: string;
  onValueChange?: (value: string) => void;
}) {
  const items = options.map((option) => ({ ...option, value: String(option.value) }));
  return (
    <Select
      name={name}
      value={
        value === undefined
          ? undefined
          : placeholder !== undefined && value === ""
            ? null
            : String(value)
      }
      defaultValue={defaultValue === undefined ? undefined : String(defaultValue)}
      disabled={disabled}
      required={required}
      items={items}
      onValueChange={(next) => {
        if (next !== null) onValueChange?.(next);
      }}
    >
      <SelectTrigger
        id={id}
        aria-label={ariaLabel}
        aria-describedby={ariaDescribedBy}
        className={cn("w-full min-w-0", className)}
      >
        <SelectValue placeholder={placeholder} />
      </SelectTrigger>
      <SelectContent align="start" alignItemWithTrigger={false}>
        {items.map((option) => (
          <SelectItem key={option.value} value={option.value} disabled={option.disabled}>
            {option.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
