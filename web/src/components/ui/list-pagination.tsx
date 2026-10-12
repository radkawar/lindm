import { useId } from "react";
import { Button } from "./button";
import { Label } from "./label";
import { SelectField } from "./select-field";

// Paging controls for a token-paged list. When the whole list fits on one page
// there is nothing to page through, so nothing renders: no disabled buttons and
// no page-size choice that cannot change what is shown.
export function ListPagination({
  label,
  previousLabel = "First page",
  onPrevious,
  onNext,
  busy = false,
  pageSize,
  pageSizes,
  onPageSizeChange,
}: {
  label: string;
  previousLabel?: string;
  onPrevious?: () => void;
  onNext?: () => void;
  busy?: boolean;
  pageSize?: number;
  pageSizes?: readonly number[];
  onPageSizeChange?: (size: number) => void;
}) {
  const id = useId();
  if (!onPrevious && !onNext) return null;
  return (
    <nav aria-label={label} className="flex flex-wrap items-center gap-2">
      <Button variant="outline" disabled={!onPrevious || busy} onClick={onPrevious}>
        {previousLabel}
      </Button>
      <Button variant="outline" disabled={!onNext || busy} onClick={onNext}>
        Next page
      </Button>
      {pageSize !== undefined && pageSizes && onPageSizeChange ? (
        <div className="ml-auto flex items-center gap-2 text-sm">
          <Label htmlFor={id} className="font-normal text-muted-foreground">
            Rows per page
          </Label>
          <SelectField
            id={id}
            className="h-8 w-20"
            value={pageSize}
            disabled={busy}
            onValueChange={(value) => onPageSizeChange(Number(value))}
            options={pageSizes.map((size) => ({ value: size, label: size }))}
          />
        </div>
      ) : null}
    </nav>
  );
}
