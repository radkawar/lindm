import { useEffect, useState, type ReactNode } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { SuggestionField } from "../../../gen/lindm/admin/v1/suggestions_pb";
import { Button } from "@/components/ui/button";
import { RpcError } from "@/components/ui/rpc-error";
import { SearchPicker, type PickerOption, type PickerProps } from "@/components/ui/search-picker";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { suggestionsQueryOptions, type SuggestionScope } from "@/lib/suggestions";

const SEARCH_DELAY_MS = 250;

function useDelayed<T>(value: T, delay: number): T {
  const [delayed, setDelayed] = useState(value);
  useEffect(() => {
    const timer = window.setTimeout(() => setDelayed(value), delay);
    return () => window.clearTimeout(timer);
  }, [value, delay]);
  return delayed;
}

function countLabel(field: SuggestionField, count: bigint): string {
  const noun = field === SuggestionField.DIRECTORY_GROUP ? "account" : "device";
  return `${count} ${noun}${count === 1n ? "" : "s"}`;
}

// Chooses a value the server has recorded (SuggestValues) instead of free text.
// The prefix search waits for a typing pause and pages with "More choices".
// allowTyped also offers the typed text, for values that may not be recorded yet.
export function SuggestionPicker({
  field,
  deviceId,
  osId,
  manager,
  note,
  placeholder,
  allowTyped = false,
  typedDescription = "Not recorded yet",
  children,
  ...props
}: PickerProps &
  SuggestionScope & {
    note?: string;
    placeholder?: string;
    allowTyped?: boolean;
    // Describes the typed choice, e.g. that a prefix matches every name it starts.
    typedDescription?: string;
    children?: ReactNode;
  }) {
  const lifetime = useAuthLifetime();
  const [search, setSearch] = useState("");
  const typed = search.trim();
  const prefix = useDelayed(typed, SEARCH_DELAY_MS);
  const [page, setPage] = useState({ prefix: "", after: "" });
  const after = page.prefix === prefix ? page.after : "";
  const list = useQuery({
    ...suggestionsQueryOptions(lifetime, { field, deviceId, osId, manager }, { prefix, after }),
    enabled: !props.disabled,
    placeholderData: keepPreviousData,
  });
  const suggestions = list.data?.suggestions ?? [];
  const choices: PickerOption[] = suggestions.map((item) => ({
    value: item.value,
    label: item.label || item.value,
    description: [
      item.label ? item.value : "",
      deviceId ? "" : `On ${countLabel(field, item.count)}`,
    ]
      .filter(Boolean)
      .join(" · "),
  }));
  if (props.value && !choices.some((item) => item.value === props.value)) {
    choices.unshift({ value: props.value, label: props.value, description: "Current selection" });
  }
  if (allowTyped && typed && !choices.some((item) => item.value === typed)) {
    choices.push({ value: typed, label: `Use “${typed}”`, description: typedDescription });
  }
  const settled = !list.isFetching && prefix === typed;
  const loading = list.isPending && !props.disabled;
  const empty = list.isSuccess && settled && suggestions.length === 0;
  const paged = after !== "" || !!list.data?.nextAfter;
  return (
    <SearchPicker
      {...props}
      search={search}
      onSearchChange={setSearch}
      options={choices}
      placeholder={placeholder}
      note={note ?? "Type the beginning of a value. Only recorded values appear, 50 at a time."}
      footer={
        loading || list.error || empty || paged ? (
          <>
            {loading ? (
              <p role="status" className="text-xs text-muted-foreground">
                Loading choices…
              </p>
            ) : null}
            {list.error ? (
              <RpcError failure={toRpcFailure(list.error)} title="Couldn't load choices">
                <Button type="button" variant="outline" onClick={() => void list.refetch()}>
                  Retry choices
                </Button>
              </RpcError>
            ) : null}
            {empty ? (
              <p className="text-xs text-muted-foreground">
                {prefix
                  ? `No recorded values start with “${prefix}”.`
                  : "No values are recorded yet."}
              </p>
            ) : null}
            {paged ? (
              <div className="flex flex-wrap gap-2">
                {after ? (
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    disabled={list.isFetching}
                    onClick={() => setPage({ prefix, after: "" })}
                  >
                    First choices
                  </Button>
                ) : null}
                {list.data?.nextAfter ? (
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    disabled={list.isFetching}
                    onClick={() => setPage({ prefix, after: list.data?.nextAfter ?? "" })}
                  >
                    More choices
                  </Button>
                ) : null}
              </div>
            ) : null}
          </>
        ) : undefined
      }
    >
      {children}
    </SearchPicker>
  );
}
