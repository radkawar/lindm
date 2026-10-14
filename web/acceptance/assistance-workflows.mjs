// SPDX-License-Identifier: Apache-2.0

// Tier 2 reconnect/recording commands for `lab vm assistance`. They drive the
// real console UI and, for refusal witnesses, the same authenticated
// AdminService endpoint the console calls. Replies carry only identities,
// public RPC codes/reasons and decoded fixture nonces, never recording bytes.
import { setTimeout as delay } from "node:timers/promises";
import { decodeNativeMarker, sampleNativeMarker } from "./assistance-marker.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const RECORDED_SCREEN = '[aria-label="Recorded screen"]';

async function adminCall(page, method, body) {
  return page.evaluate(
    async ({ method, body }) => {
      const session = await fetch("/auth/session", {
        credentials: "same-origin",
        cache: "no-store",
      });
      if (!session.ok) throw new Error("authenticated_identity_unavailable");
      const { csrfToken } = await session.json();
      if (!csrfToken) throw new Error("authenticated_csrf_unavailable");
      const response = await fetch(`/lindm.admin.v1.AdminService/${method}`, {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "Connect-Protocol-Version": "1",
          "X-CSRF-Token": csrfToken,
        },
        body: JSON.stringify(body),
      });
      const payload = await response.json();
      return {
        http_status: response.status,
        code: payload.code ?? "",
        reason: response.headers.get("Lindm-Reason") ?? "",
        observed_at: new Date().toISOString(),
      };
    },
    { method, body },
  );
}

export function createWorkflowCommands(context) {
  const page = () => context.driver().page;
  return {
    // Sends the fresh linked request from the ended session's own page.
    async reconnect(args) {
      if (!UUID.test(args.deviceId ?? "") || !UUID.test(args.sessionId ?? ""))
        throw new Error("invalid_session");
      await context
        .driver()
        .goto(`${context.origin()}/devices/${args.deviceId}/assistance/${args.sessionId}`);
      await context.ui().click({ role: "button", text: "Send a new request" });
      const deadline = Date.now() + 30_000;
      while (Date.now() < deadline) {
        const match = /\/assistance\/([0-9a-f-]{36})$/.exec(new URL(page().url()).pathname);
        if (match && match[1] !== args.sessionId) return { sessionId: match[1] };
        await delay(200);
      }
      throw new Error("reconnect_navigation_timeout");
    },
    // Follows an automatically issued request from the ended session's page.
    async followReconnect(args) {
      if (!UUID.test(args.deviceId ?? "") || !UUID.test(args.sessionId ?? ""))
        throw new Error("invalid_session");
      await context
        .driver()
        .goto(`${context.origin()}/devices/${args.deviceId}/assistance/${args.sessionId}`);
      const link = page().getByRole("link", { name: "open it", exact: true });
      await link.waitFor({ timeout: args.timeoutMs ?? 120_000 });
      await link.click();
      const match = /\/assistance\/([0-9a-f-]{36})$/.exec(new URL(page().url()).pathname);
      if (!match || match[1] === args.sessionId) throw new Error("reconnect_link_invalid");
      return { sessionId: match[1] };
    },
    // The console offers no reconnect action and the server refuses it.
    async reconnectRefused(args) {
      if (!UUID.test(args.deviceId ?? "") || !UUID.test(args.sessionId ?? ""))
        throw new Error("invalid_session");
      await context
        .driver()
        .goto(`${context.origin()}/devices/${args.deviceId}/assistance/${args.sessionId}`);
      await context.ui().wait({ role: "heading", text: "Why this session ended" });
      const offered =
        (await page().getByRole("button", { name: "Send a new request", exact: true }).count()) > 0;
      const refusal = await adminCall(page(), "ReconnectAssistanceSession", {
        requestId: crypto.randomUUID(),
        sessionId: args.sessionId,
      });
      return { ...refusal, offered };
    },
    // Plays the newest playable recording and reports which fixture nonces
    // appear, in playback order, in the decrypted WebM frames.
    async playRecording(args) {
      if (!UUID.test(args.deviceId ?? "")) throw new Error("invalid_device");
      const nonces = args.nonces ?? [];
      if (
        !Array.isArray(nonces) ||
        nonces.length > 4 ||
        nonces.some((n) => !/^[a-f0-9]{24}$/.test(n))
      )
        throw new Error("invalid_recording_nonces");
      await context.driver().goto(`${context.origin()}/devices/${args.deviceId}`);
      await context.ui().click({ role: "tab", text: "Remote assistance" });
      await context.ui().wait({ role: "button", text: "Refresh recordings" });
      await page().getByRole("button", { name: "Play", exact: true }).first().click();
      await context.ui().fill({ label: "Reason for review (audited)" }, args.reason);
      await context.ui().click({ role: "button", text: "Open recording" });
      await page()
        .locator(`${RECORDED_SCREEN} video`)
        .waitFor({ timeout: args.timeoutMs ?? 120_000 });
      // A failed play() reports the media element's own state. The page's
      // policy forbids fetching the blob back (connect-src 'self').
      const started = await page().evaluate(async (surface) => {
        const video = document.querySelector(`${surface} video`);
        video.muted = true;
        video.playbackRate = 2;
        try {
          await video.play();
          return { ok: true };
        } catch (error) {
          return {
            ok: false,
            name: String(error?.name ?? ""),
            message: String(error?.message ?? "").slice(0, 200),
            readyState: video.readyState,
            networkState: video.networkState,
            mediaError: video.error?.code ?? 0,
            mediaMessage: String(video.error?.message ?? "").slice(0, 200),
          };
        }
      }, RECORDED_SCREEN);
      if (!started.ok) {
        const error = new Error("recording_play_failed");
        error.observation = started;
        throw error;
      }
      const seen = [];
      const deadline = Date.now() + (args.timeoutMs ?? 120_000);
      let state;
      while (Date.now() < deadline) {
        const samples = await page().evaluate(sampleNativeMarker, RECORDED_SCREEN);
        state = await page().evaluate((surface) => {
          const video = document.querySelector(`${surface} video`);
          const quality = video.getVideoPlaybackQuality?.();
          return {
            ended: video.ended,
            currentTime: video.currentTime,
            videoWidth: video.videoWidth,
            videoHeight: video.videoHeight,
            frames: quality?.totalVideoFrames ?? 0,
            error: video.error?.code ?? 0,
          };
        }, RECORDED_SCREEN);
        if (state.error) throw new Error("recording_media_error");
        for (const nonce of nonces) {
          if (seen.some((entry) => entry.nonce === nonce)) continue;
          if (samples && decodeNativeMarker(samples, nonce))
            seen.push({ nonce, at: state.currentTime });
        }
        if (state.ended || seen.length === nonces.length) break;
        await delay(100);
      }
      const incomplete =
        (await page().getByText("This recording ended before its final segment.").count()) > 0;
      return {
        seen,
        videoWidth: state?.videoWidth ?? 0,
        videoHeight: state?.videoHeight ?? 0,
        frames: state?.frames ?? 0,
        complete: !incomplete,
      };
    },
    // A principal without remote_assistance.recordings.read sees metadata but
    // no playback action, and the server refuses retrieval.
    async recordingDenied(args) {
      if (!UUID.test(args.deviceId ?? "") || !UUID.test(args.recordingId ?? ""))
        throw new Error("invalid_recording");
      await context.driver().goto(`${context.origin()}/devices/${args.deviceId}`);
      await context.ui().click({ role: "tab", text: "Remote assistance" });
      await context.ui().wait({ role: "button", text: "Refresh recordings" });
      const listed =
        (await page().getByRole("heading", { name: "Recordings", exact: true }).count()) > 0;
      const playOffered =
        (await page().getByRole("button", { name: "Play", exact: true }).count()) > 0;
      const refusal = await adminCall(page(), "OpenAssistanceRecording", {
        recordingId: args.recordingId,
        reason: "lab recording retrieval permission denial",
      });
      return { ...refusal, listed, play_offered: playOffered, actor: await context.identity() };
    },
    async deleteRecording(args) {
      if (!UUID.test(args.deviceId ?? "")) throw new Error("invalid_device");
      await context.driver().goto(`${context.origin()}/devices/${args.deviceId}`);
      await context.ui().click({ role: "tab", text: "Remote assistance" });
      await context.ui().wait({ role: "button", text: "Refresh recordings" });
      await page().getByRole("button", { name: "Delete", exact: true }).first().click();
      await context.ui().fill({ label: "Reason (audited)" }, args.reason);
      await context.ui().click({ role: "button", text: "Delete recording" });
      await page().getByText("Recording deleted").first().waitFor({ timeout: 30_000 });
      return {};
    },
  };
}
