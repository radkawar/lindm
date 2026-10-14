// SPDX-License-Identifier: Apache-2.0

// Tier 3 commands for `lab vm assistance`: password-prompt guidance, the
// operator pointer and marks, shared sound and unattended access. They drive
// the real console UI; refusal witnesses use the same authenticated
// AdminService endpoint and input data channel the console uses. Replies carry
// identities, public RPC codes/reasons and measured tone levels only.
import { setTimeout as delay } from "node:timers/promises";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const RPC_METHODS = new Set([
  "ApproveApproval",
  "AuthorizeUnattendedAssistance",
  "CreateApproval",
  "CreateAssistanceSession",
  "ListUnattendedAssistance",
  "RunAssistanceCommand",
]);

async function rpc(page, method, body) {
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
        cache: "no-store",
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
        code: response.ok ? "" : (payload.code ?? ""),
        reason: response.headers.get("Lindm-Reason") ?? "",
        body: response.ok ? payload : undefined,
        observed_at: new Date().toISOString(),
      };
    },
    { method, body },
  );
}

function point(value) {
  if (!value || !(value.x >= 0 && value.x <= 1 && value.y >= 0 && value.y <= 1))
    throw new Error("invalid_point");
  return value;
}

export function createTierThreeCommands(context) {
  const page = () => context.driver().page;
  const surface = context.surface;

  // Page coordinates of a normalized point on the received frame.
  async function framePoint(target) {
    // scrollIntoViewIfNeeded waits for a stable box; the selected display's
    // video kept resizing after a display switch and it timed out
    // (layers-fedora44-tier3-19/-23 annotation-monitors). The box below is
    // read after scrolling either way.
    await page().evaluate((selector) => {
      document.querySelector(selector)?.scrollIntoView({ block: "center", inline: "center" });
    }, surface);
    const box = await page().evaluate((selector) => {
      const video = document.querySelector(`${selector} video`);
      const rect = video.getBoundingClientRect();
      return {
        x: rect.x,
        y: rect.y,
        width: rect.width,
        height: rect.height,
        videoWidth: video.videoWidth,
        videoHeight: video.videoHeight,
      };
    }, surface);
    if (!box.videoWidth || !box.videoHeight) throw new Error("video_not_rendered");
    const scale = Math.min(box.width / box.videoWidth, box.height / box.videoHeight);
    return {
      x: box.x + (box.width - box.videoWidth * scale) / 2 + target.x * box.videoWidth * scale,
      y: box.y + (box.height - box.videoHeight * scale) / 2 + target.y * box.videoHeight * scale,
    };
  }

  async function pointing(on) {
    const button = page().getByRole("button", {
      name: on ? "Point on screen" : "Stop pointing",
      exact: true,
    });
    if (await button.count()) {
      await button.waitFor({ timeout: 30_000 });
      await context.until(() => button.isEnabled(), 30_000, "pointing_unavailable");
      await button.click();
    }
  }

  async function navigateDevice(deviceId) {
    if (!UUID.test(deviceId ?? "")) throw new Error("invalid_device");
    await context.driver().goto(`${context.origin()}/devices/${deviceId}`);
    await context.ui().click({ role: "tab", text: "Remote assistance" });
    await context.ui().wait({ role: "heading", text: "Unattended access" });
  }

  return {
    // Asks the local user to enter a password themselves; the console must
    // show remote input paused once the device reports it.
    async elevationGuide(args) {
      if (typeof args.note !== "string" || args.note.length > 200 || /[\r\n]/.test(args.note))
        throw new Error("invalid_guidance_note");
      await context.ui().fill({ label: "Password prompt guidance" }, args.note);
      const command = await context.completedCommand(() =>
        context.ui().click({ role: "button", text: "Ask the user to enter it" }),
      );
      await page()
        .getByText("Remote input is paused", { exact: true })
        .waitFor({ timeout: 30_000 });
      const control = page().getByRole("button", { name: /^(Take control|Release control)$/ });
      const controlDisabled = (await control.count()) > 0 && (await control.isDisabled());
      return { command, controlDisabled };
    },
    // Replays every input kind on the device's own input channel with the
    // paused epoch and a forged later one, then asks the server for commands.
    // The device must inject nothing; the server must refuse every command.
    async pausedInputProbe(args) {
      if (!UUID.test(args.sessionId ?? "")) throw new Error("invalid_session");
      const sent = await page().evaluate(() => {
        const record = window.__lindmLabPeers?.at(-1);
        const channel = record?.inputs.find((candidate) => candidate.label === "lindm-input");
        const last = record?.lastInput;
        if (!channel || channel.readyState !== "open" || !last) return -1;
        const { display, generation, epoch } = JSON.parse(last);
        let count = 0;
        for (const fence of [epoch, epoch + 1]) {
          for (const message of [
            { t: "move", x: 0.5, y: 0.5 },
            { t: "button", b: "left", down: true },
            { t: "button", b: "left", down: false },
            { t: "wheel", dx: 0, dy: 1 },
            { t: "key", code: "KeyX", down: true },
            { t: "key", code: "KeyX", down: false },
            { t: "keysym", keysym: 0x78, down: true },
            { t: "keysym", keysym: 0x78, down: false },
          ]) {
            channel.send(JSON.stringify({ ...message, display, generation, epoch: fence }));
            count++;
          }
        }
        return count;
      });
      if (sent < 0) throw new Error("input_channel_unavailable");
      const refusals = [];
      for (const command of [
        { kind: "ASSISTANCE_COMMAND_KIND_CLIPBOARD_WRITE", text: "must-not-reach-paused-input" },
        {
          kind: "ASSISTANCE_COMMAND_KIND_SPECIAL_KEYS",
          specialKey: "ASSISTANCE_SPECIAL_KEY_CLOSE_WINDOW",
        },
      ]) {
        const refusal = await rpc(page(), "RunAssistanceCommand", {
          sessionId: args.sessionId,
          command: { requestId: crypto.randomUUID(), ...command },
        });
        refusals.push({ kind: command.kind, ...refusal, body: undefined });
      }
      return { sent, refusals, actor: await context.identity() };
    },
    // Waits until the console shows remote input resumed by the local user.
    async elevationResumed() {
      await context.until(
        async () =>
          (await page().getByText("Remote input is paused", { exact: true }).count()) === 0,
        60_000,
        "input_not_resumed",
      );
      return {};
    },
    async annotation(args) {
      const label = args.enabled ? "Show pointer" : "Stop pointer";
      const command = await context.completedCommand(() =>
        context.ui().click({ role: "button", text: label }),
      );
      await page()
        .getByRole("button", { name: args.enabled ? "Stop pointer" : "Show pointer", exact: true })
        .waitFor({ timeout: 30_000 });
      return { command };
    },
    // The console's own description of the pointer controls after a local
    // Hide, and whether enabling is still offered.
    async annotationState() {
      const show = page().getByRole("button", { name: "Show pointer", exact: true });
      return {
        showOffered: (await show.count()) > 0 && (await show.isEnabled()),
        hidden: (await page().getByText("The user hid the pointer for this session.").count()) > 0,
      };
    },
    // Rests the operator pointer on one point of the shared frame.
    async point(args) {
      const target = point(args);
      const hold = args.holdMs ?? 1500;
      if (!Number.isInteger(hold) || hold < 100 || hold > 10_000) throw new Error("invalid_hold");
      await pointing(true);
      const at = await framePoint(target);
      await page().mouse.move(at.x, at.y, { steps: 8 });
      const deadline = Date.now() + hold;
      for (let i = 0; Date.now() < deadline; i++) {
        await page().mouse.move(at.x + (i % 2), at.y);
        await delay(100);
      }
      return {};
    },
    // Drags one short-lived mark between two frame points.
    async draw(args) {
      const from = await framePoint(point(args.from));
      const to = await framePoint(point(args.to));
      await pointing(true);
      await page().mouse.move(from.x, from.y, { steps: 4 });
      await page().mouse.down();
      await page().mouse.move(to.x, to.y, { steps: 24 });
      await page().mouse.up();
      await delay(300);
      return {};
    },
    async stopPointing() {
      await pointing(false);
      return {};
    },
    async audioStatus() {
      const status = page()
        .getByText("Sound", { exact: true })
        .locator("xpath=following-sibling::*[@role='status'][1]");
      return { text: (await status.count()) ? (await status.innerText()).trim() : "" };
    },
    // Measures the shared sound with an analyser fed by the console's own
    // audio element; levels are dB relative to the median spectrum.
    async audioSpectrum(args) {
      const frequencies = args.frequencies ?? [];
      const duration = args.durationMs ?? 3000;
      if (
        !Array.isArray(frequencies) ||
        frequencies.length > 4 ||
        frequencies.some((f) => !Number.isInteger(f) || f < 100 || f > 8000) ||
        !Number.isInteger(duration) ||
        duration < 500 ||
        duration > 20_000
      )
        throw new Error("invalid_audio_probe");
      if ((await page().locator('audio[aria-label="Shared sound"]').count()) === 0)
        return { present: false, levels: {}, floor: 0, frames: 0 };
      // A real gesture on inert text lets the analyser's context start.
      await page().getByText("Sound", { exact: true }).click();
      return page().evaluate(
        async ({ frequencies, duration }) => {
          const element = document.querySelector('audio[aria-label="Shared sound"]');
          const stream = element?.srcObject;
          if (!stream || stream.getAudioTracks().length === 0)
            return { present: false, levels: {}, floor: 0, frames: 0 };
          const audio = new AudioContext();
          await audio.resume();
          const analyser = audio.createAnalyser();
          analyser.fftSize = 8192;
          analyser.smoothingTimeConstant = 0;
          audio.createMediaStreamSource(stream).connect(analyser);
          const bins = new Float32Array(analyser.frequencyBinCount);
          const sums = new Float64Array(analyser.frequencyBinCount);
          let frames = 0;
          const deadline = performance.now() + duration;
          while (performance.now() < deadline) {
            await new Promise((done) => setTimeout(done, 100));
            analyser.getFloatFrequencyData(bins);
            if (!Number.isFinite(bins[1])) continue;
            for (let i = 0; i < bins.length; i++) sums[i] += bins[i];
            frames++;
          }
          await audio.close();
          if (frames === 0) return { present: true, levels: {}, floor: 0, frames };
          const mean = Array.from(sums, (value) => value / frames);
          const sorted = mean.slice(1).sort((a, b) => a - b);
          const floor = sorted[Math.floor(sorted.length / 2)];
          const width = audio.sampleRate / analyser.fftSize;
          const levels = {};
          for (const frequency of frequencies) {
            const centre = Math.round(frequency / width);
            let peak = -Infinity;
            for (let i = Math.max(1, centre - 2); i <= centre + 2; i++)
              peak = Math.max(peak, mean[i]);
            levels[frequency] = Math.round((peak - floor) * 10) / 10;
          }
          return { present: true, levels, floor: Math.round(floor * 10) / 10, frames };
        },
        { frequencies, duration },
      );
    },
    // Requests an unattended access period through the device page form.
    async unattendedRequest(args) {
      if (!/^[a-z_][a-z0-9_.-]{0,31}$/.test(args.username ?? "")) throw new Error("invalid_user");
      if (!Number.isInteger(args.hours) || args.hours < 1 || args.hours > 720)
        throw new Error("invalid_hours");
      await navigateDevice(args.deviceId);
      await context.ui().wait({ role: "heading", text: "Request unattended access" });
      await context.ui().select("Device user", args.username);
      await context.ui().fill({ label: "Access period from now (hours)" }, String(args.hours));
      await context
        .ui()
        .fill({ label: "Reason (shown to the approver and the user)" }, args.reason);
      await context.ui().click({ role: "button", text: "Request approval" });
      await page().getByText("Approval requested").first().waitFor({ timeout: 30_000 });
      await page()
        .getByText("Waiting for a second person to approve.")
        .first()
        .waitFor({ timeout: 30_000 });
      return { actor: await context.identity() };
    },
    // The requester cannot approve their own request: the inbox offers no
    // enabled approval (it shows a disabled Approve with the reason) and the
    // server refuses it.
    async unattendedSelfApproval(args) {
      if (!UUID.test(args.approvalId ?? "")) throw new Error("invalid_approval");
      await context.driver().goto(`${context.origin()}/approvals`);
      await delay(1000);
      const offered =
        (await page()
          .getByRole("button", { name: "Approve", exact: true, disabled: false })
          .count()) > 0;
      const refusal = await rpc(page(), "ApproveApproval", {
        approvalId: args.approvalId,
        reason: "lab unattended self-approval refusal",
      });
      return { ...refusal, body: undefined, offered, actor: await context.identity() };
    },
    async unattendedActivate(args) {
      await navigateDevice(args.deviceId);
      await context.ui().click({ role: "button", text: "Activate access" });
      await page().getByText("Unattended access activated").first().waitFor({ timeout: 30_000 });
      return {};
    },
    async unattendedConnect(args) {
      await navigateDevice(args.deviceId);
      await context.ui().click({ role: "button", text: "Connect now" });
      const match = await context.until(
        () => /\/assistance\/([0-9a-f-]{36})$/.exec(new URL(page().url()).pathname),
        30_000,
        "viewer_navigation_timeout",
      );
      return { sessionId: match[1] };
    },
    // Authenticated AdminService calls for refusal witnesses and short access
    // periods the form cannot express. Methods are allow-listed.
    async tierThreeCall(args) {
      if (!RPC_METHODS.has(args.method) || typeof args.body !== "object" || args.body === null)
        throw new Error("invalid_tier_three_call");
      return { ...(await rpc(page(), args.method, args.body)), actor: await context.identity() };
    },
  };
}
