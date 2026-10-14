// SPDX-License-Identifier: Apache-2.0

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { ApprovedReferenceKind } from "../../../gen/lindm/admin/v1/approved_references_pb";
import { Button } from "@/components/ui/button";
import { RpcError } from "@/components/ui/rpc-error";
import { SearchPicker, type PickerOption, type PickerProps } from "@/components/ui/search-picker";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { approvedReferencesQueryOptions } from "./queries";

const formats: Record<string, string> = { apt: "APT", rpm: "RPM", alpm: "pacman" };
const first = { name: "", referenceId: "" };

// Chooses an approval devices report (an approved home root or package source)
// by path or repository. The reference identity is carried, never shown.
export function ApprovedReferencePicker({
  kind,
  sourceFormat,
  ...props
}: PickerProps & { kind: ApprovedReferenceKind; sourceFormat?: string }) {
  const lifetime = useAuthLifetime();
  const [search, setSearch] = useState("");
  const [prefix, setPrefix] = useState("");
  const [after, setAfter] = useState(first);
  useEffect(() => {
    const timer = window.setTimeout(() => {
      setPrefix(search.trim());
      setAfter(first);
    }, 250);
    return () => window.clearTimeout(timer);
  }, [search]);
  const list = useQuery({
    ...approvedReferencesQueryOptions(lifetime, kind, prefix, after),
    enabled: !props.disabled,
    placeholderData: keepPreviousData,
  });
  const reported = list.data?.references ?? [];
  const references = sourceFormat
    ? reported.filter((reference) => reference.format === sourceFormat)
    : reported;
  const mismatched = reported.find(
    (reference) =>
      reference.referenceId === props.value && !!sourceFormat && reference.format !== sourceFormat,
  );
  const options: PickerOption[] = references.map((reference) => ({
    value: reference.referenceId,
    label: reference.format
      ? `${formats[reference.format] ?? reference.format} · ${reference.name}`
      : reference.name,
    description: [
      reference.location,
      `Reported by ${reference.deviceCount} ${reference.deviceCount === 1n ? "device" : "devices"}`,
    ]
      .filter(Boolean)
      .join(" · "),
  }));
  if (props.value && !options.some((option) => option.value === props.value))
    options.unshift({
      value: props.value,
      label: mismatched
        ? `${formats[mismatched.format] ?? mismatched.format} · ${mismatched.name} (wrong package format)`
        : kind === ApprovedReferenceKind.HOME_ROOT
          ? "Saved home root no device reports"
          : "Saved source no device reports",
      description: mismatched
        ? `Choose a matching ${formats[sourceFormat ?? ""] ?? sourceFormat} source.`
        : "Kept as saved. Devices without this approval refuse the setting.",
      disabled: !!mismatched,
    });
  const empty = list.isSuccess && references.length === 0;
  const noun = kind === ApprovedReferenceKind.HOME_ROOT ? "home roots" : "package sources";
  return (
    <SearchPicker
      {...props}
      search={search}
      onSearchChange={setSearch}
      options={options}
      note={
        sourceFormat
          ? `Approved ${formats[sourceFormat] ?? sourceFormat} package sources reported by devices.`
          : `Approved ${noun} that devices report from their local configuration.`
      }
      footer={
        list.isPending ||
        list.error ||
        empty ||
        mismatched ||
        after.name ||
        list.data?.nextAfterName ? (
          <>
            {list.isPending && !props.disabled ? (
              <p role="status" className="text-xs text-muted-foreground">
                Loading {noun}…
              </p>
            ) : null}
            {list.error ? (
              <RpcError failure={toRpcFailure(list.error)} title={`Couldn't load ${noun}`}>
                <Button type="button" variant="outline" onClick={() => void list.refetch()}>
                  Retry
                </Button>
              </RpcError>
            ) : null}
            {mismatched ? (
              <p className="text-sm text-warning">
                The saved source does not match this package's format. Choose a matching source.
              </p>
            ) : null}
            {empty && reported.length > 0 ? (
              <p className="text-xs text-muted-foreground">
                No {formats[sourceFormat ?? ""] ?? sourceFormat} package source matches this page.
                Search by repository name.
              </p>
            ) : empty ? (
              <p className="text-xs text-muted-foreground">
                {prefix
                  ? `No reported ${noun} start with “${prefix}”.`
                  : `No device reports approved ${noun} yet. Each device's local agent configuration defines these approvals.`}
              </p>
            ) : null}
            <div className="flex flex-wrap gap-2">
              {after.name ? (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={list.isFetching}
                  onClick={() => setAfter(first)}
                >
                  First choices
                </Button>
              ) : null}
              {list.data?.nextAfterName ? (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={list.isFetching}
                  onClick={() =>
                    setAfter({
                      name: list.data?.nextAfterName ?? "",
                      referenceId: list.data?.nextAfterReferenceId ?? "",
                    })
                  }
                >
                  More choices
                </Button>
              ) : null}
            </div>
          </>
        ) : undefined
      }
    />
  );
}
