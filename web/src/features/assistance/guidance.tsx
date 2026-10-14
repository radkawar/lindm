// SPDX-License-Identifier: Apache-2.0

import { useCallback, useId, useState } from "react";
import { type AssistanceSession } from "../../../gen/lindm/admin/v1/assistance_pb";
import {
  AssistanceAudioState,
  AssistanceInputPause,
} from "../../../gen/lindm/agent/v1/assistance_guidance_pb";
import {
  AssistanceCommandKind,
  AssistancePolicyMode,
} from "../../../gen/lindm/agent/v1/assistance_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { usePrincipal } from "@/hooks/use-permissions";
import { canPermission } from "@/lib/permissions";
import { capabilityPermissions, policyMode, type CapabilityField } from "./capabilities";
import type { AssistanceCommandController } from "./commands";

// Guidance notes are bounded by the agent contract (512 bytes).
const GUIDANCE_MAX_BYTES = 512;

// Elevation guidance, the operator pointer/marks and shared sound. None of
// these grants input: guidance pauses it, annotation only draws, and sound is
// the user's local choice that they can mute or stop.
export function AssistanceGuidance({
  session,
  active,
  commands,
  pointing,
  onPointing,
  onClearMarks,
  annotationReady,
  audioStream,
  releaseControl,
}: {
  session: AssistanceSession;
  active: boolean;
  commands: AssistanceCommandController;
  pointing: boolean;
  onPointing: (pointing: boolean) => void;
  onClearMarks: () => void;
  annotationReady: boolean;
  audioStream: MediaStream | null;
  releaseControl: () => void;
}) {
  const id = useId();
  const principal = usePrincipal();
  const [note, setNote] = useState("");
  const granted = session.grantedCapabilities?.policy;
  // The element mounts only while sound is shared; bind the stream on mount.
  const attachAudio = useCallback(
    (element: HTMLAudioElement | null) => {
      if (element) element.srcObject = audioStream;
    },
    [audioStream],
  );
  const elevationPaused =
    session.inputState?.paused === true &&
    session.inputState.pause === AssistanceInputPause.ELEVATION;

  function unavailable(field: CapabilityField): string {
    if (!canPermission(principal, capabilityPermissions[field]))
      return "Your role does not allow this feature.";
    if (policyMode(session.effectiveCapabilities, field) === AssistancePolicyMode.OFF)
      return "This feature was not requested or is off in the assistance policy.";
    if (policyMode(granted, field) === AssistancePolicyMode.OFF) {
      const detail = session.grantedCapabilities?.[`${field}Reason`];
      if (detail?.startsWith("overlay_")) return "This desktop has no supported pointer overlay.";
      if (detail === "user_declined") return "The user chose not to share this.";
      return "The user or desktop did not allow this feature.";
    }
    if (!active) return "Connect to an active session before using this feature.";
    return "";
  }

  const elevationReason =
    unavailable("elevation") ||
    (elevationPaused
      ? "Remote input is already paused for the user's password."
      : session.inputState?.paused
        ? "Wait for the user to finish the local dialog."
        : commands.busy
          ? "Wait for the current request to finish."
          : new TextEncoder().encode(note).length > GUIDANCE_MAX_BYTES
            ? "Shorten the note."
            : "");
  const annotationReason =
    unavailable("annotation") ||
    (session.annotation?.hidden
      ? "The user hid the pointer for this session."
      : commands.busy
        ? "Wait for the current request to finish."
        : "");
  const annotationOn = session.annotation?.enabled === true;
  const marks = policyMode(granted, "annotation") === AssistancePolicyMode.ON;
  const audio = session.audio;
  const audioShared =
    audio?.state === AssistanceAudioState.SHARING || audio?.state === AssistanceAudioState.MUTED;

  return (
    <div className="grid gap-4 border p-3">
      {policyMode(session.effectiveCapabilities, "elevation") !== AssistancePolicyMode.OFF ? (
        <div className="grid gap-2">
          <Label htmlFor={`${id}-note`}>Password prompt guidance</Label>
          {elevationPaused ? (
            <Alert>
              <AlertTitle>Remote input is paused</AlertTitle>
              <AlertDescription>
                The user is entering a password or approval on the device. Pointer, keyboard,
                shortcuts and clipboard are paused until they choose Resume. You can still watch.
              </AlertDescription>
            </Alert>
          ) : null}
          <Textarea
            data-freeform="operator note shown to the user"
            id={`${id}-note`}
            value={note}
            disabled={!!elevationReason && !note}
            aria-describedby={`${id}-note-help`}
            autoComplete="off"
            placeholder="Optional note, for example: Enter your password to install the printer."
            onChange={(event) => setNote(event.target.value)}
          />
          <Button
            variant="outline"
            className="w-fit"
            disabled={!!elevationReason}
            aria-describedby={`${id}-note-help`}
            onClick={() => {
              releaseControl();
              void commands.run({ kind: AssistanceCommandKind.ELEVATION_GUIDANCE, text: note });
              setNote("");
            }}
          >
            Ask the user to enter it
          </Button>
          <p id={`${id}-note-help`} className="text-sm text-muted-foreground">
            {elevationReason ||
              "Pauses all your remote input before the user types. Never ask for their password."}
          </p>
        </div>
      ) : null}
      {policyMode(session.effectiveCapabilities, "annotation") !== AssistancePolicyMode.OFF ? (
        <div className="grid gap-2">
          <p className="text-sm font-medium">Pointer{marks ? " and marks" : ""}</p>
          <div className="flex flex-wrap gap-2">
            <Button
              variant="outline"
              disabled={!!annotationReason && !annotationOn}
              onClick={() => {
                if (annotationOn) onPointing(false);
                void commands.run({
                  kind: AssistanceCommandKind.ANNOTATION,
                  annotationEnabled: !annotationOn,
                });
              }}
            >
              {annotationOn ? "Stop pointer" : "Show pointer"}
            </Button>
            <Button
              variant={pointing ? "default" : "outline"}
              aria-pressed={pointing}
              disabled={!annotationOn || !annotationReady}
              onClick={() => {
                releaseControl();
                onPointing(!pointing);
              }}
            >
              {pointing ? "Stop pointing" : "Point on screen"}
            </Button>
            {marks ? (
              <Button
                variant="outline"
                disabled={!annotationOn || !annotationReady}
                onClick={onClearMarks}
              >
                Clear marks
              </Button>
            ) : null}
          </div>
          <p className="text-sm text-muted-foreground">
            {annotationReason ||
              (marks
                ? "Move to point; drag to draw a short-lived mark. Nothing is clicked or typed."
                : "Move to point. Nothing is clicked or typed.")}
          </p>
        </div>
      ) : null}
      {policyMode(session.effectiveCapabilities, "audio") !== AssistancePolicyMode.OFF ? (
        <div className="grid gap-2">
          <p className="text-sm font-medium">Sound</p>
          <p className="text-sm text-muted-foreground" role="status">
            {unavailable("audio") ||
              (audio?.state === AssistanceAudioState.MUTED
                ? "The user muted sound sharing."
                : audio?.state === AssistanceAudioState.STOPPED
                  ? "The user stopped sound sharing."
                  : audioShared
                    ? `Hearing ${[audio?.outputSource, audio?.microphoneSource ? `microphone (${audio.microphoneSource})` : ""].filter(Boolean).join(" and ")}. The user can mute or stop it.`
                    : "The user did not share sound.")}
          </p>
          {audioShared && audioStream ? (
            <audio ref={attachAudio} controls autoPlay aria-label="Shared sound" />
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
