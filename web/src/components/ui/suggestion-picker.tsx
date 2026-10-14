// SPDX-License-Identifier: Apache-2.0
// Project additions: Apache-2.0; shadcn-derived portions: MIT.
// Copyright (c) 2023 shadcn; see web/LICENSE.shadcn for the retained MIT notice.

import { useState, type ReactNode } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { SuggestionField } from "../../../gen/lindm/admin/v1/suggestions_pb";
import {
  SearchPicker,
  pickerFooter,
  type PickerOption,
  type PickerProps,
} from "@/components/ui/search-picker";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { SEARCH_DELAY_MS, useDelayed } from "@/hooks/use-delayed";
import { suggestionsQueryOptions, type SuggestionScope } from "@/lib/suggestions";

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
  const nextAfter = list.data?.nextAfter ?? "";
  return (
    <SearchPicker
      {...props}
      search={search}
      onSearchChange={setSearch}
      options={choices}
      placeholder={placeholder}
      note={note ?? "Type the beginning of a value. Only recorded values appear, 50 at a time."}
      footer={pickerFooter({
        loading: list.isPending && !props.disabled,
        error: list.error,
        onRetry: () => void list.refetch(),
        empty:
          list.isSuccess && settled && suggestions.length === 0
            ? prefix
              ? `No recorded values start with “${prefix}”.`
              : "The device has reported no values yet."
            : undefined,
        fetching: list.isFetching,
        onFirst: after ? () => setPage({ prefix, after: "" }) : undefined,
        onMore: nextAfter ? () => setPage({ prefix, after: nextAfter }) : undefined,
      })}
    >
      {children}
    </SearchPicker>
  );
}
