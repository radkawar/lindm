import { useDeferredValue, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { RpcError } from "@/components/ui/rpc-error";
import { SearchPicker, type PickerProps } from "@/components/ui/search-picker";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { auditPickerQueryOptions } from "./queries";

export function AuditActorPicker(props: PickerProps) {
  return <AuditScopePicker {...props} kind="actor" />;
}

export function AuditDevicePicker(props: PickerProps) {
  return <AuditScopePicker {...props} kind="device" />;
}

function AuditScopePicker({ kind, ...props }: PickerProps & { kind: "actor" | "device" }) {
  const lifetime = useAuthLifetime();
  const [search, setSearch] = useState("");
  const namePrefix = useDeferredValue(search);
  const [page, setPage] = useState({ namePrefix: "", token: "" });
  const afterId = page.namePrefix === namePrefix ? page.token : "";
  const list = useQuery({
    ...auditPickerQueryOptions(lifetime, kind, { namePrefix, afterId, pageSize: 100 }),
    enabled: !props.disabled,
  });
  const selected = useQuery({
    ...auditPickerQueryOptions(lifetime, kind, { id: props.value || undefined, pageSize: 1 }),
    enabled: !!props.value,
  });
  const choices = list.data?.options ?? [];
  const selectedOption = selected.data?.options.find((item) => item.value === props.value);
  const options =
    selectedOption && !choices.some((item) => item.value === props.value)
      ? [{ ...selectedOption, description: "Current selection" }, ...choices]
      : choices;
  return (
    <div className="grid gap-2">
      <SearchPicker
        {...props}
        search={search}
        onSearchChange={setSearch}
        options={options}
        note={`Enter the beginning of ${kind === "actor" ? "an account name" : "a hostname"}. Only names with recorded events appear; up to 100 choices per page.`}
      >
        {!props.disabled && list.isPending ? (
          <p role="status" className="text-xs text-muted-foreground">
            Loading choices…
          </p>
        ) : null}
        {!!props.value && selected.isPending ? (
          <p role="status" className="text-xs text-muted-foreground">
            Loading selected name…
          </p>
        ) : null}
        {list.error ? (
          <RpcError failure={toRpcFailure(list.error)}>
            <Button variant="outline" onClick={() => void list.refetch()}>
              Retry choices
            </Button>
          </RpcError>
        ) : null}
        {selected.error ? (
          <RpcError failure={toRpcFailure(selected.error)}>
            <Button variant="outline" onClick={() => void selected.refetch()}>
              Retry selected name
            </Button>
          </RpcError>
        ) : null}
        {!!props.value && selected.isSuccess && !selectedOption ? (
          <p className="text-xs text-muted-foreground">
            The selected name is no longer available. Its saved filter still applies.
          </p>
        ) : null}
        {!props.disabled && list.isSuccess && list.data.options.length === 0 ? (
          <p className="text-xs text-muted-foreground">No recorded names match this search.</p>
        ) : null}
      </SearchPicker>
      {!props.disabled ? (
        <div className="flex gap-2">
          {afterId ? (
            <Button
              variant="outline"
              disabled={list.isFetching}
              onClick={() => setPage({ namePrefix, token: "" })}
            >
              First choices
            </Button>
          ) : null}
          {list.isSuccess && list.data.nextAfterId ? (
            <Button
              variant="outline"
              disabled={list.isFetching}
              onClick={() => setPage({ namePrefix, token: list.data?.nextAfterId ?? "" })}
            >
              More choices
            </Button>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
