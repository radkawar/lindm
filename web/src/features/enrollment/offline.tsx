import { create, fromJsonString, toBinary, toJsonString } from "@bufbuild/protobuf";
import { useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useRef, useState } from "react";
import {
  CreateOfflineEnrollmentAuthorizationRequestSchema,
  ImportOfflineEnrollmentRequestRequestSchema,
  ExportOfflineEnrollmentResponseRequestSchema,
  type CreateOfflineEnrollmentAuthorizationRequest,
} from "../../../gen/lindm/admin/v1/offline_enrollment_pb";
import {
  OfflineEnrollmentAuthorizationFileSchema,
  OfflineEnrollmentRequestFileSchema,
  OfflineEnrollmentResponseFileSchema,
  type OfflineEnrollmentRequestFile,
} from "../../../gen/lindm/agent/v1/offline_enrollment_pb";
import { ExecutionRootSchema } from "../../../gen/lindm/agent/v1/trust_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import type { RpcFailure } from "@/lib/errors";
import { newRequestId } from "@/lib/ids";
import { adminClient } from "@/lib/rpc";
import { RpcError } from "@/components/ui/rpc-error";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { enrollmentFailure, validateEnrollment } from "./validation";
import { downloadEnrollmentFile } from "./download";

export function OfflineEnrollment() {
  return (
    <section className="grid gap-4" aria-label="Offline enrollment">
      <Alert>
        <AlertTitle>Offline enrollment</AlertTitle>
        <AlertDescription>
          For devices without network access. Move files by removable media, keep them readable by
          root only (mode 0600), and do not edit them.
        </AlertDescription>
      </Alert>
      <OfflineAuthorization />
      <OfflineExchange />
    </section>
  );
}

function OfflineAuthorization() {
  const lifetime = useAuthLifetime();
  const inFlight = useRef(false);
  const [captured, setCaptured] = useState<CreateOfflineEnrollmentAuthorizationRequest | null>(
    null,
  );
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<RpcFailure | null>(null);
  const [document, setDocument] = useState("");
  const [rootVersion, setRootVersion] = useState("");
  const [rootDigest, setRootDigest] = useState("");
  async function readAuthenticatedRoot(file: File | undefined) {
    if (!file || inFlight.current || captured) return;
    inFlight.current = true;
    setBusy(true);
    setFailure(null);
    try {
      if (file.size > 64 * 1024)
        throw new Error("That file is too large. Root files are 64 KiB at most.");
      const root = fromJsonString(ExecutionRootSchema, await file.text());
      validateEnrollment(ExecutionRootSchema, root);
      // ExecutionRoot has no maps: schema-order protobuf serialization matches
      // trust.ExecutionRootDigest, not BootstrapBundle's raw JSON file digest.
      const bytes = new Uint8Array(toBinary(ExecutionRootSchema, root));
      const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
      lifetime.signal.throwIfAborted();
      setRootVersion(root.version.toString());
      setRootDigest(btoa(String.fromCharCode(...digest)));
    } catch (error) {
      if (!lifetime.signal.aborted) setFailure(enrollmentFailure(error, false));
    } finally {
      inFlight.current = false;
      if (!lifetime.signal.aborted) setBusy(false);
    }
  }
  async function authorize(form: HTMLFormElement) {
    if (inFlight.current || lifetime.signal.aborted) return;
    inFlight.current = true;
    setBusy(true);
    setFailure(null);
    let submitted = false;
    try {
      let request = captured;
      if (!request) {
        const data = new FormData(form);
        // Protobuf JSON parses uint64 and bytes without a competing wire model.
        request = fromJsonString(
          CreateOfflineEnrollmentAuthorizationRequestSchema,
          JSON.stringify({
            requestId: newRequestId(),
            provisioningToken: String(data.get("token") ?? "").trim(),
            lifetimeSeconds: Number(data.get("lifetime")),
            reason: String(data.get("reason") ?? "").trim(),
            bootstrapRootVersion: String(data.get("rootVersion") ?? "").trim(),
            bootstrapRootSha256: String(data.get("rootDigest") ?? "").trim(),
          }),
        );
        validateEnrollment(CreateOfflineEnrollmentAuthorizationRequestSchema, request);
        setCaptured(request);
      }
      submitted = true;
      const response = await adminClient.createOfflineEnrollmentAuthorization(request, {
        signal: lifetime.signal,
        timeoutMs: 30_000,
      });
      lifetime.signal.throwIfAborted();
      if (!response.authorization) throw new Error("No authorization came back. Try again.");
      setDocument(
        toJsonString(OfflineEnrollmentAuthorizationFileSchema, response.authorization, {
          prettySpaces: 2,
        }),
      );
      setCaptured(null);
      form.reset();
    } catch (error) {
      if (!lifetime.signal.aborted) {
        const next = enrollmentFailure(error, submitted);
        setFailure(next);
        if (!next.ambiguous) setCaptured(null);
      }
    } finally {
      inFlight.current = false;
      if (!lifetime.signal.aborted) setBusy(false);
    }
  }
  return (
    <Card>
      <CardHeader>
        <CardTitle>1. Create an offline authorization</CardTitle>
      </CardHeader>
      <CardContent className="grid gap-4">
        <form
          className="grid gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            void authorize(event.currentTarget);
          }}
        >
          <fieldset className="grid gap-3" disabled={busy || captured !== null || !!document}>
            <label className="grid gap-1.5 text-sm font-medium">
              Provisioning token
              <Input name="token" type="password" autoComplete="off" required spellCheck={false} />
            </label>
            <label className="grid gap-1.5 text-sm font-medium">
              Valid for (seconds)
              <Input name="lifetime" type="number" defaultValue="3600" required />
            </label>
            <label className="grid gap-1.5 text-sm font-medium">
              Execution root file (execution-root.json)
              <Input
                type="file"
                accept="application/json,.json"
                onChange={(event) => void readAuthenticatedRoot(event.target.files?.[0])}
              />
            </label>
            <label className="grid gap-1.5 text-sm font-medium">
              Root version
              <Input
                name="rootVersion"
                inputMode="numeric"
                required
                value={rootVersion}
                onChange={(event) => setRootVersion(event.target.value)}
              />
            </label>
            <label className="grid gap-1.5 text-sm font-medium">
              Root SHA-256
              <Input
                name="rootDigest"
                required
                spellCheck={false}
                value={rootDigest}
                onChange={(event) => setRootDigest(event.target.value)}
              />
            </label>
            <p className="text-sm text-muted-foreground">
              Choose the execution-root.json used on the device to fill these in.
            </p>
            <label className="grid gap-1.5 text-sm font-medium">
              Reason
              <Textarea name="reason" required />
            </label>
          </fieldset>
          {captured ? (
            <TechnicalDetails items={[{ label: "Request ID", value: captured.requestId }]} />
          ) : null}
          {failure ? <RpcError failure={failure} /> : null}
          <Button type="submit" className="w-fit" disabled={busy || !!document}>
            {busy ? "Creating…" : captured ? "Try again" : "Create authorization"}
          </Button>
        </form>
        {document ? (
          <OfflineDocument
            name="lindm-offline-authorization.json"
            value={document}
            onDismiss={() => setDocument("")}
          />
        ) : null}
        <p className="text-sm">On the offline device, run as root:</p>
        <pre className="overflow-auto whitespace-pre-wrap break-all text-xs">
          /usr/libexec/lindm/lindm-agent offline-export -root /etc/lindm/execution-root.json -bundle
          /etc/lindm/bootstrap.dsse.json -file /run/lindm/lindm-offline-authorization.json -out
          /run/lindm/lindm-offline-request.json
        </pre>
        <p className="text-sm text-muted-foreground">
          If it was interrupted, run{" "}
          <code>
            /usr/libexec/lindm/lindm-agent offline-export -resume -out
            /run/lindm/lindm-offline-request.json
          </code>{" "}
          instead. Don't start over.
        </p>
      </CardContent>
    </Card>
  );
}

function OfflineExchange() {
  const lifetime = useAuthLifetime();
  const client = useQueryClient();
  const inFlight = useRef(false);
  const [request, setRequest] = useState<OfflineEnrollmentRequestFile | null>(null);
  const [busy, setBusy] = useState(false);
  const [attempt, setAttempt] = useState<{ action: "import" | "export"; reason: string } | null>(
    null,
  );
  const [failure, setFailure] = useState<RpcFailure | null>(null);
  const [reason, setReason] = useState("");
  const [status, setStatus] = useState<{
    state: string;
    deviceId: string;
    generation: string;
  } | null>(null);
  const [document, setDocument] = useState("");
  async function loadFile(file: File | undefined) {
    if (!file || busy || attempt) return;
    setFailure(null);
    setRequest(null);
    setStatus(null);
    setDocument("");
    try {
      if (file.size > 768 * 1024)
        throw new Error("That file is too large. Offline files are 768 KiB at most.");
      const text = await file.text();
      lifetime.signal.throwIfAborted();
      const value = fromJsonString(OfflineEnrollmentRequestFileSchema, text);
      validateEnrollment(OfflineEnrollmentRequestFileSchema, value);
      setRequest(value);
    } catch (error) {
      if (!lifetime.signal.aborted) setFailure(enrollmentFailure(error, false));
    }
  }
  async function exchange(action: "import" | "export") {
    if (inFlight.current || !request || lifetime.signal.aborted) return;
    inFlight.current = true;
    setBusy(true);
    setFailure(null);
    const exact = attempt ?? { action, reason: reason.trim() };
    let submitted = false;
    try {
      const options = { signal: lifetime.signal, timeoutMs: 30_000 };
      if (exact.action === "import") {
        const payload = create(ImportOfflineEnrollmentRequestRequestSchema, { request });
        validateEnrollment(ImportOfflineEnrollmentRequestRequestSchema, payload);
        setAttempt(exact);
        submitted = true;
        const result = await adminClient.importOfflineEnrollmentRequest(payload, options);
        lifetime.signal.throwIfAborted();
        if (!result.enrollment) throw new Error("No enrollment status came back. Try again.");
        setStatus({
          state: result.enrollment.state.replaceAll("_", " "),
          deviceId: result.enrollment.deviceId,
          generation: String(result.enrollment.enrollmentGeneration),
        });
        void client.invalidateQueries({ queryKey: ["pending-enrollments", lifetime.generation] });
        void client.invalidateQueries({ queryKey: ["approvals", lifetime.generation] });
      } else {
        const payload = create(ExportOfflineEnrollmentResponseRequestSchema, {
          request,
          reason: exact.reason,
        });
        validateEnrollment(ExportOfflineEnrollmentResponseRequestSchema, payload);
        setAttempt(exact);
        submitted = true;
        const result = await adminClient.exportOfflineEnrollmentResponse(payload, options);
        lifetime.signal.throwIfAborted();
        if (!result.response) throw new Error("No response file came back. Try again.");
        setDocument(
          toJsonString(OfflineEnrollmentResponseFileSchema, result.response, { prettySpaces: 2 }),
        );
      }
      setAttempt(null);
    } catch (error) {
      if (!lifetime.signal.aborted) {
        const next = enrollmentFailure(error, submitted);
        setFailure(next);
        if (!next.ambiguous) setAttempt(null);
      }
    } finally {
      inFlight.current = false;
      if (!lifetime.signal.aborted) setBusy(false);
    }
  }
  return (
    <Card>
      <CardHeader>
        <CardTitle>2. Import the device's request and export a response</CardTitle>
      </CardHeader>
      <CardContent className="grid gap-3">
        <label className="grid gap-1.5 text-sm font-medium">
          Request file from the device
          <Input
            type="file"
            accept="application/json,.json"
            disabled={busy || attempt !== null}
            onChange={(event) => void loadFile(event.target.files?.[0])}
          />
        </label>
        <p className="text-sm text-muted-foreground">
          Import the file first. If it needs approval, approve it in the{" "}
          <Link to="/approvals" className="underline underline-offset-4">
            approval inbox
          </Link>
          , then export the response using the same file.
        </p>
        <label className="grid gap-1.5 text-sm font-medium">
          Reason for export
          <Textarea
            value={reason}
            disabled={busy || attempt !== null}
            onChange={(event) => setReason(event.target.value)}
          />
        </label>
        <div className="flex flex-wrap gap-2">
          <Button
            disabled={busy || !request || (attempt !== null && attempt.action !== "import")}
            onClick={() => void exchange("import")}
          >
            {attempt?.action === "import" ? "Try import again" : "Import request"}
          </Button>
          <Button
            variant="outline"
            disabled={
              busy ||
              !request ||
              !reason.trim() ||
              (attempt !== null && attempt.action !== "export")
            }
            onClick={() => void exchange("export")}
          >
            {attempt?.action === "export" ? "Try export again" : "Export response"}
          </Button>
        </div>
        {status ? (
          <div className="grid gap-1">
            <p role="status" className="text-sm">
              Request imported. Status: {status.state}.
            </p>
            <TechnicalDetails
              items={[
                { label: "Device ID", value: status.deviceId },
                { label: "Enrollment generation", value: status.generation },
              ]}
            />
          </div>
        ) : null}
        {failure ? <RpcError failure={failure} /> : null}
        {document ? (
          <OfflineDocument
            name="lindm-offline-response.json"
            value={document}
            onDismiss={() => setDocument("")}
          />
        ) : null}
        <p className="text-sm">Copy the response file to the same device, then run as root:</p>
        <pre className="overflow-auto whitespace-pre-wrap break-all text-xs">
          /usr/libexec/lindm/lindm-agent offline-import -file /run/lindm/lindm-offline-response.json
        </pre>
      </CardContent>
    </Card>
  );
}

function OfflineDocument({
  name,
  value,
  onDismiss,
}: {
  name: string;
  value: string;
  onDismiss: () => void;
}) {
  return (
    <div className="grid gap-3 border p-3">
      <p className="text-sm">
        {name} is ready. Copy it to the device and make it readable by root only (mode 0600).
      </p>
      <Textarea
        aria-label={name}
        value={value}
        readOnly
        spellCheck={false}
        className="min-h-48 font-mono text-xs"
      />
      <Button className="w-fit" onClick={() => downloadEnrollmentFile(name, value)}>
        Download file
      </Button>
      <Button className="w-fit" variant="outline" onClick={onDismiss}>
        Dismiss
      </Button>
    </div>
  );
}
