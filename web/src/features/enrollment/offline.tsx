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
import { enrollmentFailure, validateEnrollment } from "./validation";
import { downloadEnrollmentFile } from "./download";

export function OfflineEnrollment() {
  return (
    <section className="grid gap-4" aria-label="Offline enrollment">
      <Alert>
        <AlertTitle>Offline enrollment</AlertTitle>
        <AlertDescription>
          Use the same signed installed package and independently authenticated deployment trust.
          Signed files do not contain the provisioning token or device private key. Transfer them
          through controlled media, keep files root-owned mode 0600, and do not edit their signed
          contents. Exporting a response is not proof of installation or first contact.
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
      if (file.size > 64 * 1024) throw new Error("Execution root files are limited to 64 KiB.");
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
      if (!response.authorization) throw new Error("The server returned no offline authorization.");
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
        <CardTitle>1. Issue signed offline authorization</CardTitle>
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
              Provisioning token secret
              <Input name="token" type="password" autoComplete="off" required spellCheck={false} />
            </label>
            <label className="grid gap-1.5 text-sm font-medium">
              Authorization lifetime (seconds)
              <Input name="lifetime" type="number" defaultValue="3600" required />
            </label>
            <label className="grid gap-1.5 text-sm font-medium">
              Verified execution root (JSON file)
              <Input
                type="file"
                accept="application/json,.json"
                onChange={(event) => void readAuthenticatedRoot(event.target.files?.[0])}
              />
            </label>
            <label className="grid gap-1.5 text-sm font-medium">
              Authenticated bootstrap root version
              <Input
                name="rootVersion"
                inputMode="numeric"
                required
                value={rootVersion}
                onChange={(event) => setRootVersion(event.target.value)}
              />
            </label>
            <label className="grid gap-1.5 text-sm font-medium">
              Root SHA-256 (base64 protobuf digest)
              <Input
                name="rootDigest"
                required
                spellCheck={false}
                value={rootDigest}
                onChange={(event) => setRootDigest(event.target.value)}
              />
            </label>
            <p className="text-sm text-muted-foreground">
              Select the independently authenticated execution-root.json used on the target, or
              enter its maintained execution-trust version/digest. This is not the raw JSON digest
              in a bootstrap bundle. Selecting a file does not authenticate it; the server and
              executor still verify signed continuity.
            </p>
            <label className="grid gap-1.5 text-sm font-medium">
              Audit reason
              <Textarea name="reason" required />
            </label>
          </fieldset>
          {captured ? (
            <p className="break-all text-xs text-muted-foreground">
              Request {captured.requestId}. Retries keep the same token and trust binding.
            </p>
          ) : null}
          {failure ? <RpcError failure={failure} /> : null}
          <Button type="submit" className="w-fit" disabled={busy || !!document}>
            {busy
              ? "Issuing…"
              : captured
                ? "Retry exact authorization request"
                : "Issue offline authorization"}
          </Button>
        </form>
        {document ? (
          <OfflineDocument
            name="lindm-offline-authorization.json"
            value={document}
            onDismiss={() => setDocument("")}
          />
        ) : null}
        <p className="text-sm">On the disconnected device, as root with the executor running:</p>
        <pre className="overflow-auto whitespace-pre-wrap break-all text-xs">
          /usr/libexec/lindm/lindm-agent offline-export -root /etc/lindm/execution-root.json -bundle
          /etc/lindm/bootstrap.dsse.json -file /run/lindm/lindm-offline-authorization.json -out
          /run/lindm/lindm-offline-request.json
        </pre>
        <p className="text-sm text-muted-foreground">
          Interrupted export: use{" "}
          <code>
            /usr/libexec/lindm/lindm-agent offline-export -resume -out
            /run/lindm/lindm-offline-request.json
          </code>{" "}
          with the same protected journal, never a new identity.
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
  const [status, setStatus] = useState("");
  const [document, setDocument] = useState("");
  async function loadFile(file: File | undefined) {
    if (!file || busy || attempt) return;
    setFailure(null);
    setRequest(null);
    setStatus("");
    setDocument("");
    try {
      if (file.size > 768 * 1024)
        throw new Error("Offline files are limited to 768 KiB, matching the installed agent.");
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
        if (!result.enrollment) throw new Error("The server returned no enrollment state.");
        setStatus(
          `Device ${result.enrollment.deviceId} · Generation ${result.enrollment.enrollmentGeneration} · ${result.enrollment.state.replaceAll("_", " ")}`,
        );
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
        if (!result.response) throw new Error("The server returned no signed offline response.");
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
        <CardTitle>2. Import device request and export signed response</CardTitle>
      </CardHeader>
      <CardContent className="grid gap-3">
        <label className="grid gap-1.5 text-sm font-medium">
          Device-signed request file
          <Input
            type="file"
            accept="application/json,.json"
            disabled={busy || attempt !== null}
            onChange={(event) => void loadFile(event.target.files?.[0])}
          />
        </label>
        <p className="text-sm text-muted-foreground">
          Import preserves the exact CSR, installation and transaction. If approval is required,
          finish the independent decision and requester execution in the{" "}
          <Link to="/approvals" className="underline underline-offset-4">
            approval inbox
          </Link>
          , then export using this same request file. No second token use is consumed.
        </p>
        <label className="grid gap-1.5 text-sm font-medium">
          Export audit reason
          <Textarea
            value={reason}
            disabled={busy || attempt !== null}
            onChange={(event) => setReason(event.target.value)}
          />
        </label>
        <p className="text-sm text-muted-foreground">
          Import uses the token's immutable issuance reason in the enrollment audit.
        </p>
        <div className="flex flex-wrap gap-2">
          <Button
            disabled={busy || !request || (attempt !== null && attempt.action !== "import")}
            onClick={() => void exchange("import")}
          >
            {attempt?.action === "import" ? "Retry exact import" : "Import signed request"}
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
            {attempt?.action === "export" ? "Retry exact export" : "Export signed response"}
          </Button>
        </div>
        {status ? (
          <p role="status" className="break-all text-sm">
            {status}
          </p>
        ) : null}
        {failure ? <RpcError failure={failure} /> : null}
        {document ? (
          <OfflineDocument
            name="lindm-offline-response.json"
            value={document}
            onDismiss={() => setDocument("")}
          />
        ) : null}
        <p className="text-sm">
          Return the signed response to the same protected installation, then run as root:
        </p>
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
        Signed protobuf JSON file: {name}. Save through controlled media, then set root ownership
        and mode 0600 before agent import. The console cannot enforce downloaded-file permissions.
      </p>
      <Textarea
        aria-label={name}
        value={value}
        readOnly
        spellCheck={false}
        className="min-h-48 font-mono text-xs"
      />
      <Button className="w-fit" onClick={() => downloadEnrollmentFile(name, value)}>
        Download signed file
      </Button>
      <Button className="w-fit" variant="outline" onClick={onDismiss}>
        Dismiss exported file
      </Button>
    </div>
  );
}
