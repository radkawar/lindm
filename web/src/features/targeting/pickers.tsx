import { createContext, useContext, type ReactNode } from "react";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import type { RolloutState } from "../../../gen/lindm/admin/v1/targeting_pb";
import { Button } from "@/components/ui/button";
import { SearchPicker, type PickerSlot, type PickerProps } from "@/components/ui/search-picker";
import { RpcError } from "@/components/ui/rpc-error";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { dynamicGroupsQueryOptions, rolloutsQueryOptions } from "./queries";

const Context = createContext<TargetPickers | null>(null);
export function TargetPickerProvider({
  pickers,
  children,
}: {
  pickers: TargetPickers;
  children: ReactNode;
}) {
  return <Context value={pickers}>{children}</Context>;
}
export function useTargetPickers() {
  const pickers = useContext(Context);
  if (!pickers) throw new Error("Targeting pickers must be composed by the route.");
  return pickers;
}
export type TargetPickers = {
  devicePicker: PickerSlot;
  groupPicker: PickerSlot;
  profileRevisionPicker: PickerSlot;
};
// Read-only names for saved records, composed by the route like the pickers.
export type NameSlot = (props: { value: string }) => ReactNode;
export type TargetNames = {
  deviceName: NameSlot;
  groupName: NameSlot;
  profileVersionName: NameSlot;
};

export function DynamicGroupPicker(props: PickerProps) {
  const [after, setAfter] = useState("");
  const query = useQuery(dynamicGroupsQueryOptions(useAuthLifetime(), after));
  return (
    <SearchPicker
      {...props}
      options={(query.data ?? []).map((group) => ({ value: group.groupId, label: group.name }))}
      note="Search within this page of up to 100 dynamic groups."
    >
      {query.isPending ? (
        <p role="status" className="text-sm">
          Loading dynamic groups…
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
            Retry dynamic groups
          </Button>
        </RpcError>
      ) : null}
      {!query.error && query.data?.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No dynamic groups on this page. Choose a device group instead, or create a dynamic group
          in Groups.
        </p>
      ) : null}
      {after ? (
        <Button
          type="button"
          variant="outline"
          disabled={props.disabled || query.isFetching}
          onClick={() => setAfter("")}
        >
          First dynamic groups
        </Button>
      ) : null}
      {query.data?.length === 100 ? (
        <Button
          type="button"
          variant="outline"
          disabled={props.disabled || query.isFetching}
          onClick={() => setAfter(query.data?.at(-1)?.groupId ?? "")}
        >
          More dynamic groups
        </Button>
      ) : null}
    </SearchPicker>
  );
}
// A rollout has no name of its own; its stage names identify it everywhere.
export function rolloutName(state: RolloutState) {
  return state.rollout?.rings.map((ring) => ring.name).join(", ") || "Unnamed rollout";
}

export function RolloutPicker(props: PickerProps) {
  const [after, setAfter] = useState("");
  const query = useQuery(rolloutsQueryOptions(useAuthLifetime(), after));
  return (
    <SearchPicker
      {...props}
      options={(query.data ?? []).flatMap((state) =>
        state.rollout
          ? [
              {
                value: state.rollout.rolloutId,
                label: rolloutName(state),
                description: state.paused ? "Paused" : "In progress",
              },
            ]
          : [],
      )}
      note="Search within this page of up to 100 rollouts."
    >
      {query.isPending ? (
        <p role="status" className="text-sm">
          Loading staged rollouts…
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
            Retry staged rollouts
          </Button>
        </RpcError>
      ) : null}
      {!query.error && query.data?.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No staged rollouts on this page. Leave this optional selection empty, or plan one under
          Staged rollouts above.
        </p>
      ) : null}
      {after ? (
        <Button
          type="button"
          variant="outline"
          disabled={props.disabled || query.isFetching}
          onClick={() => setAfter("")}
        >
          First rollouts
        </Button>
      ) : null}
      {query.data?.length === 100 ? (
        <Button
          type="button"
          variant="outline"
          disabled={props.disabled || query.isFetching}
          onClick={() => setAfter(query.data?.at(-1)?.rollout?.rolloutId ?? "")}
        >
          More rollouts
        </Button>
      ) : null}
    </SearchPicker>
  );
}
