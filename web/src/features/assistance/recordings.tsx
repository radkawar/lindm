// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import { toast } from "sonner";
import {
  AssistanceRecordingArchiveState,
  DeleteAssistanceRecordingRequestSchema,
  type AssistanceRecording,
  type DeleteAssistanceRecordingRequest,
} from "../../../gen/lindm/admin/v1/assistance_pb";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty-state";
import { Label } from "@/components/ui/label";
import { RpcError } from "@/components/ui/rpc-error";
import { StatusBadge, type StatusTone } from "@/components/ui/status-badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { useExactRequest } from "@/hooks/use-exact-request";
import { usePrincipal } from "@/hooks/use-permissions";
import { toRpcFailure, type RpcFailure } from "@/lib/errors";
import { newRequestId } from "@/lib/ids";
import { canPermission } from "@/lib/permissions";
import { REASON_MAX_UNITS } from "@/lib/reason";
import { adminClient } from "@/lib/rpc";
import { TimeCell } from "./display";
import { assistanceRecordingsQueryOptions } from "./queries";
import { RECORDING_MEDIA_TYPE, readRecording } from "./recording-stream";
import { validateRequest } from "@/lib/validation";

export const RECORDINGS_READ_PERMISSION = "remote_assistance.recordings.read";
export const RECORDINGS_DELETE_PERMISSION = "remote_assistance.recordings.delete";

const archiveStates: Record<AssistanceRecordingArchiveState, { label: string; tone: StatusTone }> =
  {
    [AssistanceRecordingArchiveState.UNSPECIFIED]: { label: "Unknown", tone: "neutral" },
    [AssistanceRecordingArchiveState.PENDING]: { label: "Waiting for user", tone: "info" },
    [AssistanceRecordingArchiveState.RECORDING]: { label: "Recording", tone: "warning" },
    [AssistanceRecordingArchiveState.COMPLETE]: { label: "Complete", tone: "success" },
    [AssistanceRecordingArchiveState.INCOMPLETE]: { label: "Incomplete", tone: "warning" },
    [AssistanceRecordingArchiveState.FAILED]: {
      label: "Not recorded (failed)",
      tone: "destructive",
    },
    [AssistanceRecordingArchiveState.DECLINED]: { label: "Declined by user", tone: "neutral" },
    [AssistanceRecordingArchiveState.DELETED]: { label: "Deleted", tone: "neutral" },
  };

export function RecordingStateBadge({ state }: { state: AssistanceRecordingArchiveState }) {
  const presentation =
    archiveStates[state] ?? archiveStates[AssistanceRecordingArchiveState.UNSPECIFIED];
  return <StatusBadge status={presentation.tone}>{presentation.label}</StatusBadge>;
}

// Device-detail archive list. Metadata is visible to fleet readers; playback
// and deletion need their own permissions and grant no live access.
export function DeviceRecordings({ deviceId }: { deviceId: string }) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const [pageToken, setPageToken] = useState("");
  const [playing, setPlaying] = useState<AssistanceRecording | null>(null);
  const [deleting, setDeleting] = useState<AssistanceRecording | null>(null);
  const query = useQuery(assistanceRecordingsQueryOptions(lifetime, deviceId, pageToken));
  const failure = query.error ? toRpcFailure(query.error) : null;
  const data = failure ? undefined : query.data;
  const canRead = canPermission(principal, RECORDINGS_READ_PERMISSION);
  const canDelete = canPermission(principal, RECORDINGS_DELETE_PERMISSION);
  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="font-semibold">Recordings</h3>
        <Button variant="outline" disabled={query.isFetching} onClick={() => void query.refetch()}>
          Refresh recordings
        </Button>
      </div>
      {query.isPending ? <p role="status">Loading recordings…</p> : null}
      {failure ? <RpcError failure={failure} title="Couldn't load recordings" /> : null}
      {data?.recordings.length === 0 ? (
        <EmptyState
          title="No recordings"
          description="Sessions are recorded only when policy allows it and the user is told."
        />
      ) : null}
      {data?.recordings.length ? (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Status</TableHead>
              <TableHead>Recorded</TableHead>
              <TableHead>Size and length</TableHead>
              <TableHead>Kept until</TableHead>
              <TableHead>
                <span className="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.recordings.map((recording) => (
              <TableRow key={recording.id}>
                <TableCell>
                  <RecordingStateBadge state={recording.state} />
                  <p className="text-xs text-muted-foreground">
                    {recording.required ? "Required" : "Optional"}
                  </p>
                </TableCell>
                <TableCell>
                  <TimeCell value={recording.startedAt ?? recording.createdAt} />
                </TableCell>
                <TableCell>
                  {(Number(recording.storedBytes) / (1024 * 1024)).toFixed(1)} MiB,{" "}
                  {recording.durationSeconds} s
                </TableCell>
                <TableCell>
                  <TimeCell value={recording.retainUntil} />
                </TableCell>
                <TableCell className="flex flex-wrap gap-2">
                  {canRead &&
                  (recording.state === AssistanceRecordingArchiveState.COMPLETE ||
                    recording.state === AssistanceRecordingArchiveState.INCOMPLETE) ? (
                    <Button variant="outline" size="sm" onClick={() => setPlaying(recording)}>
                      Play
                    </Button>
                  ) : null}
                  {canDelete &&
                  recording.state !== AssistanceRecordingArchiveState.DELETED &&
                  recording.state !== AssistanceRecordingArchiveState.PENDING &&
                  recording.state !== AssistanceRecordingArchiveState.RECORDING ? (
                    <Button variant="outline" size="sm" onClick={() => setDeleting(recording)}>
                      Delete
                    </Button>
                  ) : null}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      ) : null}
      <div className="flex gap-2">
        <Button
          variant="outline"
          disabled={!pageToken || query.isFetching}
          onClick={() => setPageToken("")}
        >
          Newest recordings
        </Button>
        <Button
          variant="outline"
          disabled={!data?.nextPageToken || query.isFetching}
          onClick={() => setPageToken(data?.nextPageToken ?? "")}
        >
          Older recordings
        </Button>
      </div>
      {playing ? (
        <RecordingPlayer key={playing.id} recording={playing} onClose={() => setPlaying(null)} />
      ) : null}
      {deleting ? (
        <RecordingDeletion
          key={deleting.id}
          deviceId={deviceId}
          recording={deleting}
          onClose={() => setDeleting(null)}
        />
      ) : null}
    </div>
  );
}

// Playback opens one audited, expiring retrieval and keeps the decrypted
// stream only in this dialog's memory; closing it releases the object URL.
function RecordingPlayer({
  recording,
  onClose,
}: {
  recording: AssistanceRecording;
  onClose: () => void;
}) {
  const id = useId();
  const lifetime = useAuthLifetime();
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [loaded, setLoaded] = useState(0);
  const [failure, setFailure] = useState<RpcFailure | null>(null);
  const [invalid, setInvalid] = useState("");
  const [video, setVideo] = useState<{ url: string; complete: boolean } | null>(null);
  const controller = useRef<AbortController | null>(null);

  useEffect(
    () => () => {
      controller.current?.abort();
    },
    [],
  );
  useEffect(() => {
    if (!video) return;
    return () => URL.revokeObjectURL(video.url);
  }, [video]);

  async function open(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    const trimmed = reason.trim();
    if (!trimmed) {
      setInvalid("Enter why you need to review this recording. The reason is audited.");
      return;
    }
    setInvalid("");
    setFailure(null);
    setBusy(true);
    const abort = new AbortController();
    controller.current = abort;
    const signal = AbortSignal.any([abort.signal, lifetime.signal]);
    try {
      const opened = await adminClient.openAssistanceRecording(
        { recordingId: recording.id, reason: trimmed },
        { signal },
      );
      const metadata = opened.recording;
      if (!metadata || metadata.id !== recording.id || opened.mediaType !== RECORDING_MEDIA_TYPE)
        throw new Error("The retrieval does not match this recording.");
      const playback = await readRecording(
        metadata.segments,
        Number(metadata.storedBytes),
        (sequence, readSignal) =>
          adminClient.readAssistanceRecording(
            { retrievalId: opened.retrievalId, sequence },
            { signal: readSignal },
          ),
        signal,
        setLoaded,
      );
      const blob = new Blob(playback.parts as BlobPart[], { type: RECORDING_MEDIA_TYPE });
      setVideo({ url: URL.createObjectURL(blob), complete: playback.complete });
    } catch (error) {
      if (!signal.aborted) setFailure(toRpcFailure(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open onOpenChange={(open) => (!open ? onClose() : undefined)}>
      <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>Play recording</DialogTitle>
          <DialogDescription>
            Opening a recording is audited with your reason. It does not give access to the live
            device.
          </DialogDescription>
        </DialogHeader>
        {video ? (
          <div className="grid gap-2">
            {!video.complete ? (
              <p role="status" className="text-sm">
                This recording ended before its final segment. It plays up to where it stopped.
              </p>
            ) : null}
            <div aria-label="Recorded screen">
              <video className="w-full bg-viewer" controls src={video.url} />
            </div>
          </div>
        ) : (
          <form className="grid gap-3" onSubmit={(event) => void open(event)}>
            <div className="grid gap-2">
              <Label htmlFor={`${id}-reason`}>Reason for review (audited)</Label>
              <Textarea
                data-freeform="audit reason for retrieval"
                id={`${id}-reason`}
                value={reason}
                readOnly={busy}
                maxLength={REASON_MAX_UNITS}
                onChange={(event) => setReason(event.target.value)}
              />
            </div>
            {invalid ? (
              <p role="alert" className="text-sm text-destructive">
                {invalid}
              </p>
            ) : null}
            {failure ? <RpcError failure={failure} title="Couldn't open recording" /> : null}
            {busy ? (
              <p role="status" className="text-sm">
                Loaded {loaded} of {recording.segments} parts…
              </p>
            ) : null}
            <div className="flex gap-2">
              <Button type="submit" disabled={busy}>
                {busy ? "Opening…" : "Open recording"}
              </Button>
              <Button type="button" variant="outline" onClick={onClose}>
                Cancel
              </Button>
            </div>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}

function RecordingDeletion({
  deviceId,
  recording,
  onClose,
}: {
  deviceId: string;
  recording: AssistanceRecording;
  onClose: () => void;
}) {
  const id = useId();
  const lifetime = useAuthLifetime();
  const queryClient = useQueryClient();
  const exact = useExactRequest<DeleteAssistanceRecordingRequest>();
  const [reason, setReason] = useState("");

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void exact.submit({
      capture: () => {
        const request = create(DeleteAssistanceRecordingRequestSchema, {
          requestId: newRequestId(),
          recordingId: recording.id,
          reason: reason.trim(),
        });
        validateRequest(DeleteAssistanceRecordingRequestSchema, request);
        return request;
      },
      send: (request, options) => adminClient.deleteAssistanceRecording(request, options),
      failureTitle: "Delete recording",
      onSuccess: async () => {
        await queryClient.invalidateQueries({
          queryKey: ["assistance-recordings", lifetime.generation, deviceId],
        });
        toast.success("Recording deleted");
        onClose();
      },
    });
  }

  return (
    <Dialog open onOpenChange={(open) => (!open ? onClose() : undefined)}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Delete recording</DialogTitle>
          <DialogDescription>
            The encrypted recording and its key are destroyed. Audit metadata remains.
          </DialogDescription>
        </DialogHeader>
        <form className="grid gap-3" onSubmit={submit}>
          <div className="grid gap-2">
            <Label htmlFor={`${id}-reason`}>Reason (audited)</Label>
            <Textarea
              data-freeform="audit reason for deletion"
              id={`${id}-reason`}
              value={reason}
              readOnly={exact.busy || exact.ambiguous}
              maxLength={REASON_MAX_UNITS}
              onChange={(event) => setReason(event.target.value)}
            />
          </div>
          {exact.invalid ? (
            <p role="alert" className="text-sm text-destructive">
              {exact.invalid}
            </p>
          ) : null}
          {exact.failure ? (
            <RpcError failure={exact.failure} title="Recording not deleted" />
          ) : null}
          <div className="flex gap-2">
            <Button type="submit" variant="destructive" disabled={exact.busy}>
              {exact.busy ? "Deleting…" : exact.ambiguous ? "Try again" : "Delete recording"}
            </Button>
            <Button type="button" variant="outline" disabled={exact.busy} onClick={onClose}>
              Cancel
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
