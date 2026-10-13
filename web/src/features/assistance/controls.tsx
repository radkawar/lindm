import { getOption } from "@bufbuild/protobuf";
import { field as validationRules } from "@bufbuild/protovalidate/gen/buf/validate/validate_pb.js";
import { useEffect, useId, useLayoutEffect, useRef, useState, type RefObject } from "react";
import { type AssistanceSession } from "../../../gen/lindm/admin/v1/assistance_pb";
import {
  AssistanceCommandKind,
  AssistanceCommandStatus,
  AssistanceCommandSchema,
  AssistancePolicyMode,
  AssistanceSpecialKey,
} from "../../../gen/lindm/agent/v1/assistance_pb";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { RpcError } from "@/components/ui/rpc-error";
import { SelectField } from "@/components/ui/select-field";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { canPermission } from "@/lib/permissions";
import { capabilityPermissions, policyMode, type CapabilityField } from "./capabilities";
import type { AssistanceCommandController } from "./commands";
import type { KeyboardMode } from "./input";

const textRules = getOption(AssistanceCommandSchema.field.text, validationRules).type;
if (textRules.case !== "string" || !textRules.value.maxBytes)
  throw new Error("Assistance command text requires a schema bound.");
const ASSISTANCE_TEXT_MAX_UNITS = Number(textRules.value.maxBytes);

const specialKeys = [
  { value: AssistanceSpecialKey.SWITCH_WINDOW, label: "Switch window" },
  { value: AssistanceSpecialKey.SHOW_APPLICATIONS, label: "Show applications" },
  { value: AssistanceSpecialKey.OPEN_TERMINAL, label: "Open terminal" },
  { value: AssistanceSpecialKey.CLOSE_WINDOW, label: "Close window" },
];

const completedLabels: Record<number, string> = {
  [AssistanceCommandKind.CLIPBOARD_WRITE]:
    "Clipboard text shared. The user can paste it on the device.",
  [AssistanceCommandKind.CLIPBOARD_READ]:
    "Clipboard text received. Choose Copy clipboard to copy it here.",
  [AssistanceCommandKind.SPECIAL_KEYS]: "Special keys sent to the device.",
  [AssistanceCommandKind.SELECT_DISPLAY]: "Shared display changed.",
  [AssistanceCommandKind.MESSAGE]: "Message sent to the device.",
};

const incompleteLabels: Record<string, string> = {
  command_state_lost:
    "The request has no recorded outcome. Check the device before sending it again.",
  command_expired: "The request expired without confirmation of completion.",
  session_ended: "The session ended before this request finished.",
  content_expired: "Clipboard text is no longer available. Choose Read clipboard again.",
};

export function AssistanceControls({
  session,
  active,
  controlOn,
  frameReady,
  commands,
  message,
  onMessage,
  onSpecialKey,
  keyboardMode,
  onKeyboardMode,
  releaseControl,
  portalContainer,
}: {
  session: AssistanceSession;
  active: boolean;
  controlOn: boolean;
  frameReady: boolean;
  commands: AssistanceCommandController;
  message: string;
  onMessage: (value: string) => void;
  onSpecialKey: (key: AssistanceSpecialKey) => void;
  keyboardMode: KeyboardMode;
  onKeyboardMode: (mode: KeyboardMode) => void;
  releaseControl: () => void;
  portalContainer: RefObject<HTMLDivElement | null>;
}) {
  const id = useId();
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const [specialKey, setSpecialKey] = useState(AssistanceSpecialKey.SWITCH_WINDOW);
  const [clipboardBusy, setClipboardBusy] = useState(false);
  const [browserError, setBrowserError] = useState("");
  const [copied, setCopied] = useState(false);
  const clipboardEpoch = useRef(0);
  const clipboardInFlight = useRef(false);
  const busy = commands.busy || clipboardBusy;
  const granted = session.grantedCapabilities?.policy;
  const { result: commandResult, clipboardReady, clearResult } = commands;

  useLayoutEffect(() => {
    if (active) return;
    clipboardEpoch.current++;
    setCopied(false);
    setClipboardBusy(false);
    setBrowserError("");
  }, [active]);

  useEffect(() => {
    const clear = () => {
      clipboardEpoch.current++;
      setCopied(false);
      setClipboardBusy(false);
    };
    const visibility = () => {
      if (document.hidden) clear();
    };
    document.addEventListener("visibilitychange", visibility);
    window.addEventListener("blur", clear);
    lifetime.signal.addEventListener("abort", clear, { once: true });
    return () => {
      clear();
      window.removeEventListener("blur", clear);
      document.removeEventListener("visibilitychange", visibility);
      lifetime.signal.removeEventListener("abort", clear);
    };
  }, [lifetime.signal]);

  useEffect(() => {
    if (!clipboardReady || !commandResult) return;
    const timer = window.setTimeout(() => {
      commandResult.text = "";
      clearResult();
    }, 30_000);
    return () => window.clearTimeout(timer);
  }, [commandResult, clipboardReady, clearResult]);

  function reason(field: CapabilityField, minimum = AssistancePolicyMode.LIMITED) {
    if (!active) return "Connect to an active session before using this feature.";
    if (!canPermission(principal, capabilityPermissions[field]))
      return "Your role does not allow this feature.";
    if (policyMode(session.effectiveCapabilities, field) < minimum)
      return "This feature was not requested or is off in the assistance policy.";
    if (policyMode(granted, field) < minimum) {
      const detail = session.grantedCapabilities?.[`${field}Reason`];
      if (detail === "portal_clipboard_not_granted")
        return "The desktop did not grant clipboard sharing.";
      if (detail === "portal_clipboard_unsupported")
        return "This desktop does not support clipboard sharing.";
      if (detail === "portal_clipboard_denied") return "The desktop denied clipboard sharing.";
      if (detail === "portal_control_not_granted")
        return "The desktop did not grant keyboard control.";
      if (detail === "only_one_monitor_granted") return "The user shared only one display.";
      return "The user or desktop did not allow this feature.";
    }
    if (busy) return "Wait for the current request to finish.";
    return "";
  }
  const clipboardReason = reason("clipboard");
  const readReason = reason("clipboard", AssistancePolicyMode.ON);
  const keyboardReason =
    active && !session.controlGranted ? "The user allowed viewing only." : reason("keyboard");
  const physicalReason =
    active && !session.controlGranted
      ? "The user allowed viewing only."
      : reason("keyboard", AssistancePolicyMode.ON);
  const specialReason =
    physicalReason ||
    (!frameReady
      ? "Wait for the selected screen to appear."
      : !controlOn
        ? "Choose Take control before sending special keys."
        : "");
  const displayReason =
    reason("display", AssistancePolicyMode.ON) ||
    (!frameReady ? "Wait for the selected screen to appear." : "");
  const messageReason = reason("messages");
  const clipboardAvailable = window.isSecureContext && !!navigator.clipboard;

  async function sendClipboard() {
    if (clipboardReason || !clipboardAvailable || clipboardInFlight.current) return;
    clipboardInFlight.current = true;
    const epoch = clipboardEpoch.current;
    setClipboardBusy(true);
    setBrowserError("");
    setCopied(false);
    try {
      // Invoked directly by a click; the browser owns permission and activation checks.
      let text = await navigator.clipboard.readText();
      if (lifetime.signal.aborted || epoch !== clipboardEpoch.current) return;
      const sent = commands.run({ kind: AssistanceCommandKind.CLIPBOARD_WRITE, text });
      text = "";
      await sent;
    } catch {
      if (epoch === clipboardEpoch.current)
        setBrowserError(
          "Could not read your clipboard. Allow clipboard access in your browser. Retry sending the clipboard.",
        );
    } finally {
      clipboardInFlight.current = false;
      if (epoch === clipboardEpoch.current) setClipboardBusy(false);
    }
  }

  async function copyClipboard() {
    const result = commands.result;
    if (
      !result ||
      !commands.clipboardReady ||
      readReason ||
      !clipboardAvailable ||
      clipboardInFlight.current
    )
      return;
    const epoch = clipboardEpoch.current;
    clipboardInFlight.current = true;
    setClipboardBusy(true);
    setBrowserError("");
    try {
      // Separate click retains user activation even when the remote read took time.
      await navigator.clipboard.writeText(result.text);
      if (!lifetime.signal.aborted && epoch === clipboardEpoch.current) {
        commands.clearResult();
        setCopied(true);
      }
    } catch {
      if (epoch === clipboardEpoch.current)
        setBrowserError(
          "Could not copy clipboard text. Allow clipboard access in your browser. Retry copying the clipboard.",
        );
    } finally {
      clipboardInFlight.current = false;
      if (epoch === clipboardEpoch.current) setClipboardBusy(false);
    }
  }

  const result = commands.result;
  const outcome =
    result?.status === AssistanceCommandStatus.SUCCEEDED
      ? result.kind === AssistanceCommandKind.CLIPBOARD_READ && !commands.clipboardReady
        ? "Clipboard text is no longer available. Choose Read clipboard again."
        : completedLabels[result.kind] || "Request completed."
      : result
        ? incompleteLabels[result.reason] ||
          (result.status === AssistanceCommandStatus.EXPIRED
            ? "The request expired without confirmation of completion."
            : result.status === AssistanceCommandStatus.CANCELLED
              ? "The request ended with cancellation."
              : "The request did not report successful completion.")
        : "";
  return (
    <div className="grid gap-4 border p-3">
      <div className="grid gap-2">
        <h2 className="font-semibold">Clipboard</h2>
        <div className="flex flex-wrap gap-2">
          <Button
            variant="outline"
            disabled={!!clipboardReason || !clipboardAvailable}
            aria-describedby={`${id}-clipboard`}
            onClick={() => void sendClipboard()}
          >
            Send clipboard
          </Button>
          <Button
            variant="outline"
            disabled={!!readReason}
            aria-describedby={
              clipboardAvailable && readReason && readReason === clipboardReason
                ? `${id}-clipboard`
                : `${id}-read`
            }
            onClick={() => {
              setCopied(false);
              void commands.run({ kind: AssistanceCommandKind.CLIPBOARD_READ });
            }}
          >
            Read clipboard
          </Button>
          {commands.clipboardReady ? (
            <Button
              variant="outline"
              disabled={!!readReason || !clipboardAvailable}
              aria-describedby={
                clipboardAvailable && readReason && readReason === clipboardReason
                  ? `${id}-clipboard`
                  : `${id}-read`
              }
              onClick={() => void copyClipboard()}
            >
              Copy clipboard
            </Button>
          ) : null}
        </div>
        <p id={`${id}-clipboard`} className="text-sm text-muted-foreground">
          {!clipboardAvailable
            ? "Clipboard access requires a supported browser and a secure connection."
            : clipboardReason || "Send plain text from your clipboard to the device."}
        </p>
        {!clipboardAvailable || readReason !== clipboardReason || !readReason ? (
          <p id={`${id}-read`} className="text-sm text-muted-foreground">
            {!clipboardAvailable
              ? "Copying requires clipboard access in a supported browser."
              : readReason ||
                "Read the device clipboard. Choose Copy clipboard to copy the received text."}
          </p>
        ) : null}
        {copied ? <p role="status">Clipboard text copied.</p> : null}
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="grid gap-2">
          <Label htmlFor={`${id}-keyboard`}>Keyboard mode</Label>
          <SelectField
            portalContainer={portalContainer}
            id={`${id}-keyboard`}
            value={keyboardMode}
            disabled={!!keyboardReason}
            aria-describedby={`${id}-keyboard-help`}
            options={[
              { value: "text", label: "Text" },
              { value: "physical", label: "Physical keys", disabled: !!physicalReason },
            ]}
            onValueChange={(value) => {
              releaseControl();
              onKeyboardMode(value === "physical" ? "physical" : "text");
            }}
          />
          <p id={`${id}-keyboard-help`} className="text-sm text-muted-foreground">
            {keyboardReason ||
              "Text mode sends printable symbols. Physical keys use the device's keyboard layout."}
          </p>
        </div>
        <div className="grid gap-2">
          <Label htmlFor={`${id}-special`}>Special keys</Label>
          <SelectField
            portalContainer={portalContainer}
            id={`${id}-special`}
            value={specialKey}
            disabled={!!specialReason}
            aria-describedby={`${id}-special-help`}
            options={specialKeys}
            onValueChange={(value) => setSpecialKey(Number(value) as AssistanceSpecialKey)}
          />
          <Button
            variant="outline"
            disabled={!!specialReason}
            aria-describedby={`${id}-special-help`}
            onClick={() => {
              if (!specialReason) onSpecialKey(specialKey);
            }}
          >
            Send special keys
          </Button>
          <p id={`${id}-special-help`} className="text-sm text-muted-foreground">
            {specialReason || "Send a shortcut to the shared desktop."}
          </p>
        </div>
      </div>
      <div className="grid gap-2">
        <Label htmlFor={`${id}-display`}>Select display</Label>
        <SelectField
          portalContainer={portalContainer}
          id={`${id}-display`}
          // Always controlled: Base UI fixes the mode on first render, before the
          // agent reports displays, so `undefined` there hid every later selection.
          value={session.selectedDisplayId}
          placeholder="No display shared yet"
          disabled={!!displayReason || session.displays.length < 2}
          aria-describedby={`${id}-display-help`}
          options={session.displays.map((display, index) => ({
            value: display.id,
            label: display.label || `Display ${index + 1}`,
          }))}
          onValueChange={(displayId) => {
            if (displayId !== session.selectedDisplayId) {
              releaseControl();
              void commands.run({ kind: AssistanceCommandKind.SELECT_DISPLAY, displayId });
            }
          }}
        />
        <p id={`${id}-display-help`} className="text-sm text-muted-foreground">
          {displayReason ||
            (session.displays.length === 0
              ? "No shared displays are available."
              : session.displays.length === 1
                ? "The user shared only one display."
                : "Choose one of the displays the user shared.")}
        </p>
      </div>
      <div className="grid gap-2">
        <Label htmlFor={`${id}-message`}>Message</Label>
        <Textarea
          id={`${id}-message`}
          data-freeform="operator message shown to the user"
          value={message}
          disabled={!!messageReason}
          aria-describedby={`${id}-message-help`}
          autoComplete="off"
          maxLength={ASSISTANCE_TEXT_MAX_UNITS}
          onChange={(event) => onMessage(event.target.value)}
        />
        <Button
          variant="outline"
          disabled={!!messageReason || message.trim() === ""}
          aria-describedby={`${id}-message-help`}
          onClick={() => void commands.run({ kind: AssistanceCommandKind.MESSAGE, text: message })}
        >
          Send message
        </Button>
        <p id={`${id}-message-help`} className="text-sm text-muted-foreground">
          {messageReason || "Send a plain-text notification to the user on the device."}
        </p>
        {session.grantedCapabilities &&
        (session.grantedCapabilities.clipboardReason ||
          session.grantedCapabilities.keyboardReason ||
          session.grantedCapabilities.displayReason ||
          session.grantedCapabilities.messagesReason) ? (
          <details className="text-sm">
            <summary>Details for support</summary>
            <dl className="select-text">
              {session.grantedCapabilities.clipboardReason ? (
                <div>
                  <dt>Clipboard</dt>
                  <dd>{session.grantedCapabilities.clipboardReason}</dd>
                </div>
              ) : null}
              {session.grantedCapabilities.keyboardReason ? (
                <div>
                  <dt>Keyboard</dt>
                  <dd>{session.grantedCapabilities.keyboardReason}</dd>
                </div>
              ) : null}
              {session.grantedCapabilities.displayReason ? (
                <div>
                  <dt>Displays</dt>
                  <dd>{session.grantedCapabilities.displayReason}</dd>
                </div>
              ) : null}
              {session.grantedCapabilities.messagesReason ? (
                <div>
                  <dt>Messages</dt>
                  <dd>{session.grantedCapabilities.messagesReason}</dd>
                </div>
              ) : null}
            </dl>
          </details>
        ) : null}
      </div>
      {commands.invalid ? (
        <p role="alert" className="text-sm text-destructive">
          {commands.invalid}
        </p>
      ) : null}
      {commands.failure ? (
        <RpcError failure={commands.failure} title="Couldn't confirm the request" />
      ) : null}
      {browserError ? (
        <p role="alert" className="text-sm text-destructive">
          {browserError}
        </p>
      ) : null}
      {commands.pending ? (
        <>
          <p role="status">{commands.notice || "Checking the request outcome…"}</p>
          <Button variant="outline" onClick={commands.check}>
            Check result
          </Button>
        </>
      ) : null}
      {!commands.pending && !result && commands.notice ? (
        <p role="status">{commands.notice}</p>
      ) : null}
      {result ? (
        <div role="status">
          <p>{outcome}</p>
          {result.reason ? (
            <details>
              <summary>Details for support</summary>
              <p className="select-text">{result.reason}</p>
            </details>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
