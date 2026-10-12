import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useId, useRef, useState } from "react";
import { Cloud, Laptop } from "lucide-react";
import { toast } from "sonner";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import type { PickerSlot } from "@/components/ui/search-picker";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { Textarea } from "@/components/ui/textarea";
import { newRequestId } from "@/lib/ids";
import { classifyRpcFailure, toRpcFailure, type RpcFailure } from "@/lib/errors";
import { reasonError } from "@/lib/reason";
import { adminClient } from "@/lib/rpc";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { IssueProvisioningToken, ProvisioningTokens } from "./provisioning";
import { EnrollmentSecretDialog, type EnrollmentCredential } from "./token-result";
import { EnrollmentGrants } from "./grants";
import { PendingEnrollments } from "./pending";
import { OfflineEnrollment } from "./offline";

type GrantPayload = { requestId: string; lifetimeSeconds: number; reason: string };

export function EnrollmentView({
  accountPicker,
  groupPicker,
  profileRevisionPicker,
}: {
  accountPicker: PickerSlot;
  groupPicker: PickerSlot;
  profileRevisionPicker: PickerSlot;
}) {
  const lifetime = useAuthLifetime();
  const [method, setMethod] = useState<"grant" | "provisioning" | null>(null);
  const [credential, setCredential] = useState<EnrollmentCredential | null>(null);
  const [activeTab, setActiveTab] = useState<"grants" | "tokens">("grants");
  const [offline, setOffline] = useState(false);
  const tabId = useId();
  const [tokenFormVersion, setTokenFormVersion] = useState(0);
  const tabs = useRef<(HTMLButtonElement | null)[]>([]);
  useEffect(() => {
    const dismiss = () => setCredential(null);
    lifetime.signal.addEventListener("abort", dismiss, { once: true });
    return () => lifetime.signal.removeEventListener("abort", dismiss);
  }, [lifetime]);
  function issued(value: EnrollmentCredential) {
    if (lifetime.signal.aborted) return;
    setMethod(null);
    setActiveTab(value.kind === "grant" ? "grants" : "tokens");
    setCredential(value);
    if (value.kind === "provisioning") setTokenFormVersion((version) => version + 1);
  }
  return (
    <section className="grid min-w-0 gap-6">
      <PageHeader
        title="Enroll a device"
        description="Choose how you want to add devices to your fleet."
      />
      <PendingEnrollments />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <Laptop className="mb-2 size-6 text-primary" aria-hidden="true" />
            <CardTitle>Enroll one device now</CardTitle>
            <CardDescription>For setting up one machine from its terminal.</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-4">
            <p className="text-sm">A single-use code that expires in 5 minutes.</p>
            <p className="text-sm text-muted-foreground">
              You'll get the install and enroll commands for apt or dnf.
            </p>
            <Button className="w-fit" aria-haspopup="dialog" onClick={() => setMethod("grant")}>
              Create one-time code
            </Button>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <Cloud className="mb-2 size-6 text-primary" aria-hidden="true" />
            <CardTitle>Automatic enrollment</CardTitle>
            <CardDescription>
              For cloud-init, Kickstart, autoinstall and device imaging.
            </CardDescription>
          </CardHeader>
          <CardContent className="grid gap-4">
            <p className="text-sm">A reusable token. Defaults to 24 hours and 100 uses.</p>
            <p className="text-sm text-muted-foreground">
              You'll get an installer snippet. Add the token at install time, not to a saved image.
            </p>
            <Button
              className="w-fit"
              aria-haspopup="dialog"
              onClick={() => setMethod("provisioning")}
            >
              Create provisioning token
            </Button>
          </CardContent>
        </Card>
      </div>
      <p className="text-sm text-muted-foreground">
        Device without network access?{" "}
        <Button
          variant="link"
          className="h-auto p-0 align-baseline"
          aria-haspopup="dialog"
          onClick={() => setOffline(true)}
        >
          Enroll devices at offline sites
        </Button>
      </p>
      <Dialog open={method === "grant"} onOpenChange={(open) => setMethod(open ? "grant" : null)}>
        <DialogContent keepMounted className="max-h-[90svh] overflow-y-auto sm:max-w-xl">
          <IssueGrant onIssued={issued} onCancel={() => setMethod(null)} />
        </DialogContent>
      </Dialog>
      <Dialog
        open={method === "provisioning"}
        onOpenChange={(open) => setMethod(open ? "provisioning" : null)}
      >
        <DialogContent
          keepMounted
          className="flex max-h-[90svh] flex-col gap-0 overflow-hidden p-0 sm:max-w-2xl"
        >
          <IssueProvisioningToken
            key={tokenFormVersion}
            accountPicker={accountPicker}
            groupPicker={groupPicker}
            profileRevisionPicker={profileRevisionPicker}
            onCancel={() => setMethod(null)}
            onIssued={(result) =>
              issued({
                kind: "provisioning",
                id: result.tokenId,
                secret: result.secret || null,
                expiresAt: result.expiresAt,
                deliveryUnknown: result.secretDeliveryUnknown || !result.secret,
              })
            }
          />
        </DialogContent>
      </Dialog>
      {credential ? (
        <EnrollmentSecretDialog
          key={credential.id}
          credential={credential}
          onDismiss={() => setCredential(null)}
        />
      ) : null}
      <section className="grid min-w-0 gap-4" aria-label="Enrollment credentials">
        <div
          role="tablist"
          aria-label="Enrollment credentials"
          className="flex overflow-x-auto border-b"
        >
          {(["grants", "tokens"] as const).map((tab, index) => (
            <button
              key={tab}
              ref={(element) => {
                tabs.current[index] = element;
              }}
              type="button"
              role="tab"
              id={`${tabId}-${tab}`}
              aria-controls={`${tabId}-${tab}-panel`}
              aria-selected={activeTab === tab}
              tabIndex={activeTab === tab ? 0 : -1}
              className="shrink-0 border-b-2 border-transparent px-4 py-3 text-sm font-medium text-muted-foreground focus-visible:outline focus-visible:outline-ring aria-selected:border-primary aria-selected:text-foreground"
              onClick={() => setActiveTab(tab)}
              onKeyDown={(event) => {
                if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
                event.preventDefault();
                const next = event.key === "Home" ? 0 : event.key === "End" ? 1 : 1 - index;
                setActiveTab(next === 0 ? "grants" : "tokens");
                tabs.current[next]?.focus();
              }}
            >
              {tab === "grants" ? "One-time codes" : "Provisioning tokens"}
            </button>
          ))}
        </div>
        <section
          role="tabpanel"
          id={`${tabId}-grants-panel`}
          aria-labelledby={`${tabId}-grants`}
          hidden={activeTab !== "grants"}
          tabIndex={0}
        >
          <EnrollmentGrants />
        </section>
        <section
          role="tabpanel"
          id={`${tabId}-tokens-panel`}
          aria-labelledby={`${tabId}-tokens`}
          hidden={activeTab !== "tokens"}
          tabIndex={0}
        >
          <ProvisioningTokens />
        </section>
      </section>
      <Dialog open={offline} onOpenChange={setOffline}>
        <DialogContent keepMounted className="max-h-[90svh] overflow-y-auto sm:max-w-3xl">
          <DialogHeader>
            <DialogTitle>Enroll devices at offline sites</DialogTitle>
            <DialogDescription>
              For devices without network access. Move files by removable media, keep them readable
              by root only (mode 0600), and do not edit them.
            </DialogDescription>
          </DialogHeader>
          <OfflineEnrollment />
        </DialogContent>
      </Dialog>
    </section>
  );
}

function IssueGrant({
  onIssued,
  onCancel,
}: {
  onIssued: (grant: EnrollmentCredential) => void;
  onCancel: () => void;
}) {
  const authLifetime = useAuthLifetime();
  const client = useQueryClient();
  const inFlight = useRef(false);
  const submitted = useRef<GrantPayload | null>(null);
  const [lifetime, setLifetime] = useState("300");
  const [reason, setReason] = useState("");
  const [requestId, setRequestId] = useState(newRequestId);
  const [fieldError, setFieldError] = useState("");
  const [failure, setFailure] = useState<RpcFailure | null>(null);
  const frozen = submitted.current !== null;
  const issue = useMutation({
    retry: false,
    meta: { authGeneration: authLifetime.generation },
    gcTime: 0,
    mutationFn: async (payload: GrantPayload) => {
      const response = await adminClient.createEnrollmentGrant(payload, {
        signal: authLifetime.signal,
      });
      authLifetime.signal.throwIfAborted();
      if (!response.grantId.trim())
        throw new Error("The code may not have been created. Try again.");
      const deliveryUnknown = response.secretDeliveryUnknown || !response.secret;
      onIssued({
        kind: "grant",
        id: response.grantId,
        expiresAt: response.expiresAt,
        secret: deliveryUnknown ? null : response.secret,
        deliveryUnknown,
      });
      return { deliveryUnknown };
    },
    onSuccess: (result) => {
      submitted.current = null;
      setRequestId(newRequestId());
      setFailure(null);
      setReason("");
      setLifetime("300");
      void client.invalidateQueries({ queryKey: ["enrollment-grants", authLifetime.generation] });
      if (!authLifetime.signal.aborted) {
        if (result.deliveryUnknown)
          toast.error("Couldn't show the code", {
            description: "Revoke it and create a new one.",
          });
        else toast.success("One-time code created");
      }
    },
    onError: (error) => {
      const next = toRpcFailure(error);
      setFailure(next);
      if (!authLifetime.signal.aborted) {
        const feedback = classifyRpcFailure(next);
        const notify = feedback.tone === "destructive" ? toast.error : toast;
        notify(feedback.title, { description: feedback.action });
      }
    },
    onSettled: () => {
      inFlight.current = false;
    },
  });
  return (
    <>
      <DialogHeader>
        <DialogTitle>Enroll one device now</DialogTitle>
        <DialogDescription>Create a single-use code for one machine.</DialogDescription>
      </DialogHeader>
      <form
        className="grid gap-4"
        onSubmit={(event) => {
          event.preventDefault();
          if (inFlight.current) return;
          if (submitted.current) {
            inFlight.current = true;
            issue.mutate(submitted.current);
            return;
          }
          const nextReason = reasonError(reason);
          if (nextReason) {
            setFieldError(nextReason);
            return;
          }
          setFieldError("");
          submitted.current = {
            requestId,
            lifetimeSeconds: Number(lifetime),
            reason: reason.trim(),
          };
          inFlight.current = true;
          issue.mutate(submitted.current);
        }}
      >
        <Label htmlFor="grant-lifetime">Code expires after</Label>
        <SelectField
          id="grant-lifetime"
          value={lifetime}
          disabled={issue.isPending || frozen}
          onValueChange={setLifetime}
          options={[
            { value: "60", label: "1 minute" },
            { value: "300", label: "5 minutes (default)" },
            { value: "900", label: "15 minutes" },
          ]}
        />
        <p className="text-sm text-muted-foreground">
          You'll get the install commands after you create the code.
        </p>
        <Label htmlFor="grant-reason">Reason</Label>
        <Textarea
          id="grant-reason"
          required
          maxLength={512}
          value={reason}
          readOnly={issue.isPending || frozen}
          onChange={(event) => setReason(event.target.value)}
        />
        {fieldError ? (
          <p role="alert" className="text-sm text-destructive">
            {fieldError}
          </p>
        ) : null}
        {failure ? (
          <RpcError failure={failure}>
            {failure.ambiguous ? <p>Try again to check. The code can't be shown twice.</p> : null}
          </RpcError>
        ) : null}
        <TechnicalDetails items={[{ label: "Request ID", value: requestId }]} />
        <div className="flex flex-wrap gap-2">
          <Button type="submit" disabled={issue.isPending}>
            {issue.isPending ? "Creating code…" : failure ? "Try again" : "Create one-time code"}
          </Button>
          <Button
            type="button"
            variant="outline"
            disabled={issue.isPending || failure?.ambiguous}
            onClick={onCancel}
          >
            Cancel
          </Button>
          {failure && !failure.ambiguous ? (
            <Button
              type="button"
              variant="outline"
              disabled={issue.isPending}
              onClick={() => {
                if (inFlight.current) return;
                submitted.current = null;
                setRequestId(newRequestId());
                setFailure(null);
              }}
            >
              Edit
            </Button>
          ) : null}
        </div>
      </form>
    </>
  );
}
