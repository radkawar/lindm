// SPDX-License-Identifier: Apache-2.0

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useDeferredValue, useState } from "react";
import type { SecretSummary } from "../../../gen/lindm/admin/v1/secrets_pb";
import { Button } from "@/components/ui/button";
import { RpcError } from "@/components/ui/rpc-error";
import { SearchPicker, type PickerProps } from "@/components/ui/search-picker";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { purposeLabels } from "./material";
import { secretQueryOptions, secretsQueryOptions } from "./queries";

export function SecretPicker({
  onSelect,
  ...props
}: PickerProps & { onSelect?: (secret: SecretSummary | undefined) => void }) {
  const lifetime = useAuthLifetime();
  const [search, setSearch] = useState("");
  const namePrefix = useDeferredValue(search.trim());
  const [page, setPage] = useState({ namePrefix: "", token: "" });
  const pageToken = page.namePrefix === namePrefix ? page.token : "";
  const query = useQuery({
    ...secretsQueryOptions(lifetime, 100, pageToken, namePrefix),
    placeholderData: keepPreviousData,
  });
  const selected = useQuery({
    ...secretQueryOptions(lifetime, props.value),
    enabled: !!props.value,
  });
  const secrets = query.error ? [] : [...(query.data?.secrets ?? [])];
  const selectedSecret = selected.error ? undefined : selected.data?.secret;
  if (selectedSecret && !secrets.some((secret) => secret.secretId === selectedSecret.secretId)) {
    secrets.unshift(selectedSecret);
  }
  return (
    <SearchPicker
      {...props}
      onChange={(value) => {
        if (onSelect) {
          onSelect(secrets.find((secret) => secret.secretId === value));
        } else {
          props.onChange(value);
        }
      }}
      search={search}
      onSearchChange={setSearch}
      disabled={props.disabled}
      options={secrets.map((secret) => ({
        value: secret.secretId,
        label: secret.displayName.trim() || "Unnamed secret",
        description: purposeLabels[secret.purpose] ?? "Unrecognized purpose",
      }))}
      note="Enter the beginning of a secret name. Up to 100 choices per page."
      footer={
        <div className="grid gap-2 p-2">
          {query.isPending ? (
            <p role="status" className="text-xs text-muted-foreground">
              Loading secrets…
            </p>
          ) : null}
          {query.error ? (
            <RpcError failure={toRpcFailure(query.error)}>
              <Button
                type="button"
                variant="outline"
                disabled={query.isFetching}
                onClick={() => void query.refetch()}
              >
                Retry
              </Button>
            </RpcError>
          ) : null}
          {query.isSuccess && query.data.secrets.length === 0 ? (
            <p className="text-xs text-muted-foreground">
              {namePrefix ? "No secret names start with this search." : "No secrets stored yet."}
            </p>
          ) : null}
          {pageToken || query.data?.nextPageToken ? (
            <div className="flex flex-wrap gap-2">
              <Button
                type="button"
                variant="outline"
                disabled={query.isFetching || !pageToken}
                onClick={() => setPage({ namePrefix, token: "" })}
              >
                First choices
              </Button>
              <Button
                type="button"
                variant="outline"
                disabled={query.isFetching || !query.data?.nextPageToken}
                onClick={() => setPage({ namePrefix, token: query.data?.nextPageToken ?? "" })}
              >
                More choices
              </Button>
            </div>
          ) : null}
        </div>
      }
    >
      {selected.error ? (
        <RpcError failure={toRpcFailure(selected.error)}>
          <Button
            type="button"
            variant="outline"
            disabled={selected.isFetching}
            onClick={() => void selected.refetch()}
          >
            Retry
          </Button>
        </RpcError>
      ) : null}
    </SearchPicker>
  );
}

export function SecretReferencePicker(props: PickerProps) {
  let secretId = "";
  if (props.value) {
    try {
      const reference: unknown = JSON.parse(props.value);
      if (
        reference &&
        typeof reference === "object" &&
        "secretId" in reference &&
        typeof reference.secretId === "string"
      ) {
        secretId = reference.secretId;
      }
    } catch {
      // An incomplete draft has no selected server record.
    }
  }
  return (
    <>
      {props.name ? <input type="hidden" name={props.name} value={props.value} /> : null}
      <SecretPicker
        {...props}
        name={undefined}
        value={secretId}
        onSelect={(secret) =>
          props.onChange(
            secret
              ? JSON.stringify({
                  secretId: secret.secretId,
                  subjectBindingId: secret.subjectBindingId,
                  version: secret.currentVersion.toString(),
                  purpose: secret.purpose,
                })
              : "",
          )
        }
      />
    </>
  );
}
