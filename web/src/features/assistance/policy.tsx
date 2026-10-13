import { create } from "@bufbuild/protobuf";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { toast } from "sonner";
import {
  UpdateAssistancePolicyRequestSchema,
  type UpdateAssistancePolicyRequest,
} from "../../../gen/lindm/admin/v1/assistance_pb";
import {
  AssistancePolicySchema,
  type AssistancePolicy,
} from "../../../gen/lindm/agent/v1/assistance_pb";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { RpcError } from "@/components/ui/rpc-error";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { useExactRequest } from "@/hooks/use-exact-request";
import { toRpcFailure } from "@/lib/errors";
import { newRequestId } from "@/lib/ids";
import { adminClient } from "@/lib/rpc";
import { CapabilityFields } from "./capabilities";
import { assistancePolicyQueryOptions } from "./queries";
import { validateRequest } from "@/lib/validation";

export function AssistancePolicyDialog({ deviceId }: { deviceId: string }) {
  const lifetime = useAuthLifetime();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState<AssistancePolicy | null>(null);
  const query = useQuery({ ...assistancePolicyQueryOptions(lifetime, deviceId), enabled: open });
  const exact = useExactRequest<UpdateAssistancePolicyRequest>();
  const value = draft ?? query.data?.policy ?? create(AssistancePolicySchema);
  const locked = exact.busy || exact.ambiguous;

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void exact.submit({
      capture: () => {
        if (!query.data || query.error) throw new Error("Refresh the policy before saving.");
        const request = create(UpdateAssistancePolicyRequestSchema, {
          requestId: newRequestId(),
          deviceId,
          policy: value,
        });
        validateRequest(UpdateAssistancePolicyRequestSchema, request);
        return request;
      },
      send: (request, options) => adminClient.updateAssistancePolicy(request, options),
      failureTitle: "Assistance policy",
      onSuccess: async () => {
        setDraft(null);
        await queryClient.invalidateQueries({
          queryKey: assistancePolicyQueryOptions(lifetime, deviceId).queryKey,
        });
        toast.success("Assistance policy saved");
        setOpen(false);
      },
    });
  }

  return (
    <>
      <Button variant="outline" aria-haspopup="dialog" onClick={() => setOpen(true)}>
        Assistance policy
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent keepMounted className="max-h-[90svh] overflow-y-auto sm:max-w-xl">
          <DialogHeader>
            <DialogTitle>Assistance policy</DialogTitle>
            <DialogDescription>
              Choose the features that operators can request on this device.
            </DialogDescription>
          </DialogHeader>
          <form className="grid gap-4" onSubmit={submit}>
            {query.isPending ? <p role="status">Loading policy…</p> : null}
            {query.error ? (
              <RpcError
                failure={toRpcFailure(query.error)}
                title="Couldn't load assistance policy"
              />
            ) : null}
            <CapabilityFields
              value={value}
              ceiling={query.error ? undefined : query.data?.ceiling}
              manage
              disabled={locked || !query.data || !!query.error}
              onChange={(field, mode) =>
                setDraft(create(AssistancePolicySchema, { ...value, [field]: mode }))
              }
            />
            {exact.invalid ? (
              <p role="alert" className="text-sm text-destructive">
                {exact.invalid}
              </p>
            ) : null}
            {exact.failure ? (
              <RpcError failure={exact.failure} title="Couldn't save assistance policy" />
            ) : null}
            <div className="flex flex-wrap gap-2">
              <Button
                type="submit"
                disabled={exact.busy || (!exact.ambiguous && (!query.data || !!query.error))}
              >
                {exact.busy ? "Saving…" : exact.ambiguous ? "Retry same save" : "Save policy"}
              </Button>
              <Button
                type="button"
                variant="outline"
                disabled={locked || query.isFetching}
                onClick={() => {
                  setDraft(null);
                  void query.refetch();
                }}
              >
                Refresh policy
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </>
  );
}
