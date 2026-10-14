#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { createInterface } from "node:readline";
import { join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { ChromiumDriver, UI } from "./drivers.mjs";
import { enroll, openSignIn, signIn } from "./journey.mjs";
import { privateDirectory, readPrivateJSON, writePrivate } from "./private-files.mjs";
import {
  startupFailure,
  startupObservation,
  startupStage,
  visibleOutcome,
} from "./assistance-startup.mjs";
import { decodeNativeMarker, sampleNativeMarker } from "./assistance-marker.mjs";
import { END_HEADINGS } from "./assistance-end.mjs";

// Line-oriented private control protocol for `lab vm assistance`
// (internal/vmlab/vm_assistance_browser_linux.go). Each stdin line is one JSON
// command and each stdout line is exactly one JSON reply. The operator signs
// in through the real console UI; replies and screenshots never carry
// credentials and browser exceptions are reduced to stable codes.
process.umask(0o077);

const SURFACE = '[aria-label^="Remote screen"]';
let config;
let driver;
let ui;
let startStage = "configuration";

function starting(stage) {
  startStage = stage;
  startupStage(stage);
}

let lastCommand;
let commandURL;
let commandCSRF;
let fixtureNonce;

async function completedCommand(action) {
  const previous = lastCommand?.requestId;
  await action();
  return until(
    () => {
      if (!lastCommand || lastCommand.requestId === previous) return null;
      if (lastCommand.status === "ASSISTANCE_COMMAND_STATUS_SUCCEEDED" || lastCommand.status === 2)
        return lastCommand;
      if (!["ASSISTANCE_COMMAND_STATUS_PENDING", 1].includes(lastCommand.status))
        throw new Error("guest_command_failed");
      return null;
    },
    45_000,
    "guest_command_timeout",
  );
}

// Observe the console's own peer. Split lanes additionally restrict TURN URLs
// to the SSH-forwarded endpoint to model a browser outside the controller LAN;
// the console's relay-only policy and all other RTC configuration stay intact.
function observePeers(forwardedTURNURL) {
  const Native = window.RTCPeerConnection;
  const peers = [];
  Object.defineProperty(window, "__lindmLabPeers", { value: peers });
  window.RTCPeerConnection = class extends Native {
    constructor(configuration, ...rest) {
      if (forwardedTURNURL) {
        configuration = {
          ...configuration,
          iceServers: (configuration?.iceServers ?? []).flatMap((server) => {
            const urls = [server.urls].flat().filter((url) => url === forwardedTURNURL);
            return urls.length ? [{ ...server, urls }] : [];
          }),
        };
      }
      super(configuration, ...rest);
      const record = {
        pc: this,
        policy: configuration?.iceTransportPolicy ?? "all",
        channels: [],
        inputs: [],
      };
      peers.push(record);
      this.addEventListener("datachannel", (event) => {
        record.channels.push(event.channel.label);
        record.inputs.push(event.channel);
      });
    }
  };
}

async function observeMedia(surface) {
  const video = document.querySelector(`${surface} video`);
  const record = window.__lindmLabPeers?.at(-1);
  const result = {
    videoWidth: video?.videoWidth ?? 0,
    videoHeight: video?.videoHeight ?? 0,
    decodedFrames: video?.webkitDecodedFrameCount ?? 0,
    framesDecoded: 0,
    connectionState: record?.pc.connectionState ?? "",
    transportPolicy: record?.policy ?? "",
    remoteApplication: /^m=application /m.test(record?.pc.remoteDescription?.sdp ?? ""),
    dataChannels: [...(record?.channels ?? [])],
    localCandidateType: "",
    localRelayProtocol: "",
    localCandidateURL: "",
    remoteCandidateType: "",
    openInputChannels:
      record?.inputs.filter((channel) => channel.readyState === "open").length ?? 0,
    markerHead: -1,
    controlButton: [...document.querySelectorAll("button")].some((node) =>
      /^(Take control|Release control)$/.test(node.innerText.trim()),
    ),
  };
  if (!record || record.pc.connectionState === "closed") return result;
  const stats = await record.pc.getStats();
  let pair;
  stats.forEach((report) => {
    if (report.type === "inbound-rtp" && report.kind === "video")
      result.framesDecoded = report.framesDecoded ?? 0;
    if (report.type === "transport" && report.selectedCandidatePairId)
      pair = stats.get(report.selectedCandidatePairId);
  });
  if (pair) {
    result.localCandidateType = stats.get(pair.localCandidateId)?.candidateType ?? "";
    result.remoteCandidateType = stats.get(pair.remoteCandidateId)?.candidateType ?? "";
    result.localRelayProtocol = stats.get(pair.localCandidateId)?.relayProtocol ?? "";
    result.localCandidateURL = stats.get(pair.localCandidateId)?.url ?? "";
  }
  return result;
}

async function nativeMarker() {
  const samples = await driver.page.evaluate(sampleNativeMarker, SURFACE);
  return decodeNativeMarker(samples, fixtureNonce);
}

async function mediaObservation() {
  const result = await driver.page.evaluate(observeMedia, SURFACE);
  result.markerHead = (await nativeMarker())?.head ?? -1;
  return result;
}

async function until(check, timeoutMs, code) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await check();
    if (value) return value;
    await delay(200);
  }
  throw new Error(code);
}

function timeout(args) {
  const value = args.timeoutMs ?? config.actionTimeoutMs;
  if (!Number.isInteger(value) || value < 1000 || value > 600_000)
    throw new Error("invalid_deadline");
  return value;
}

const commands = {
  async start() {
    starting("chromium_launch");
    driver = new ChromiumDriver();
    await driver.open(config);
    starting("browser_setup");
    await driver.context.addInitScript(observePeers, config.forwardedTurnUrl ?? "");
    await driver.context.grantPermissions(["clipboard-read", "clipboard-write"], {
      origin: config.origin,
    });
    driver.page.on("request", (request) => {
      if (
        !/\/(CreateAssistanceSession|RunAssistanceCommand)$/.test(new URL(request.url()).pathname)
      )
        return;
      commandURL = request.url().replace(/\/CreateAssistanceSession$/, "/RunAssistanceCommand");
      commandCSRF = request.headers()["x-csrf-token"];
    });
    driver.page.on("response", async (response) => {
      if (!/\/(RunAssistanceCommand|GetAssistanceCommand)$/.test(new URL(response.url()).pathname))
        return;
      if (!response.ok()) return;
      try {
        const { result } = await response.json();
        if (result) {
          const { requestId, kind, status, reason } = result;
          lastCommand = { requestId, kind, status, reason };
        }
      } catch {
        // An aborted response cannot establish command completion.
      }
    });
    ui = new UI(driver, config.actionTimeoutMs);
    starting("navigation");
    await openSignIn(ui, config.origin);
    starting("authenticator");
    await driver.authenticator([]);
    starting("enrollment");
    await enroll(ui, config);
    starting("sign_in");
    await signIn(ui, config);
    return { engine: "chromium", version: driver.metadata.browserVersion };
  },
  async identity() {
    return driver.page.evaluate(async () => {
      const response = await fetch("/auth/session", {
        credentials: "same-origin",
        cache: "no-store",
      });
      if (!response.ok) throw new Error("authenticated_identity_unavailable");
      const principal = await response.json();
      if (!principal.id || !Array.isArray(principal.permissions))
        throw new Error("authenticated_identity_incomplete");
      // Whitelist public actor facts. Never return CSRF, cookies or credentials.
      return {
        id: principal.id,
        display: principal.displayName || principal.subject || principal.id,
        role: principal.role,
        permissions: principal.permissions,
        observed_at: new Date().toISOString(),
      };
    });
  },
  async refuseMode(args) {
    if (!/^[0-9a-f-]{36}$/.test(args.deviceId ?? "") || !["view", "control"].includes(args.mode))
      throw new Error("invalid_mode_boundary");
    await driver.goto(`${config.origin}/devices/${args.deviceId}`);
    await ui.click({ role: "tab", text: "Remote assistance" });
    await ui.wait({ role: "heading", text: "Session history" });
    // The request form appears only once readiness answers READY.
    await driver.page
      .getByText("Checking assistance availability…", { exact: true })
      .waitFor({ state: "hidden" });
    const requestForm =
      (await driver.page
        .getByRole("button", { name: "Request remote assistance", exact: true })
        .count()) > 0;
    let controlOption = false;
    if (requestForm) {
      await driver.page.getByRole("combobox", { name: "Mode", exact: true }).click();
      controlOption =
        (await driver.page
          .getByRole("option", { name: "View and request control", exact: true })
          .count()) > 0;
      await driver.page.keyboard.press("Escape");
    }
    const actor = await commands.identity();
    const refusal = await driver.page.evaluate(async ({ deviceId, mode }) => {
      const session = await fetch("/auth/session", {
        credentials: "same-origin",
        cache: "no-store",
      });
      if (!session.ok) throw new Error("authenticated_identity_unavailable");
      const { csrfToken } = await session.json();
      if (!csrfToken) throw new Error("authenticated_csrf_unavailable");
      const requestId = crypto.randomUUID();
      const response = await fetch("/lindm.admin.v1.AdminService/CreateAssistanceSession", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "Connect-Protocol-Version": "1",
          "X-CSRF-Token": csrfToken,
        },
        body: JSON.stringify({
          requestId,
          deviceId,
          mode: mode === "control" ? "ASSISTANCE_MODE_CONTROL" : "ASSISTANCE_MODE_VIEW",
          reason: "lab independent assistance mode permission denial",
          maxDurationSeconds: 600,
        }),
      });
      const body = await response.json();
      return {
        request_id: requestId,
        device_id: deviceId,
        mode,
        code: body.code ?? "",
        reason: response.headers.get("Lindm-Reason") ?? "",
        http_status: response.status,
        observed_at: new Date().toISOString(),
      };
    }, args);
    if (
      refusal.http_status !== 403 ||
      refusal.code !== "permission_denied" ||
      refusal.reason !== "permission_denied"
    )
      throw new Error("mode_permission_not_denied");
    return { ...refusal, actor, request_form: requestForm, control_option: controlOption };
  },
  async reopen(args) {
    if (
      !/^[0-9a-f-]{36}$/.test(args.deviceId ?? "") ||
      !/^[0-9a-f-]{36}$/.test(args.sessionId ?? "")
    )
      throw new Error("invalid_session");
    await driver.goto(config.origin);
    await signIn(ui, config);
    const actor = await commands.identity();
    await driver.goto(`${config.origin}/devices/${args.deviceId}/assistance/${args.sessionId}`);
    return actor;
  },
  async request(args) {
    if (!/^[0-9a-f-]{36}$/.test(args.deviceId ?? "")) throw new Error("invalid_device");
    fixtureNonce = undefined;
    const label = { view: "View screen", control: "View and request control" }[args.mode];
    if (!label) throw new Error("invalid_mode");
    await driver.goto(`${config.origin}/devices/${args.deviceId}`);
    await ui.click({ role: "tab", text: "Remote assistance" });
    await ui.select("Mode", label);
    await ui.fill({ label: "Maximum duration (minutes, 1 to 30)" }, String(args.minutes));
    await ui.fill({ css: 'textarea[id$="-reason"]' }, args.reason);
    for (const [label, option] of Object.entries(args.capabilities ?? {}))
      await ui.select(label, option);
    await ui.click({ role: "button", text: "Request remote assistance" });
    const match = await until(
      () => /\/assistance\/([0-9a-f-]{36})$/.exec(new URL(driver.page.url()).pathname),
      config.actionTimeoutMs,
      "viewer_navigation_timeout",
    );
    return { sessionId: match[1] };
  },
  async media(args) {
    const minFrames = args.minFrames ?? 1;
    let last;
    try {
      return await until(
        async () => {
          last = await mediaObservation();
          return last.videoWidth > 0 && last.decodedFrames >= minFrames ? last : null;
        },
        timeout(args),
        "video_frames_timeout",
      );
    } catch (error) {
      if (last) error.observation = last;
      throw error;
    }
  },
  async observe() {
    return mediaObservation();
  },
  async control() {
    const take = driver.page.getByRole("button", { name: "Take control", exact: true });
    if (await take.count()) await take.click();
    await ui.wait({ role: "button", text: "Release control" });
    return {};
  },
  async click(args) {
    const { x, y } = args;
    if (!(x >= 0 && x <= 1 && y >= 0 && y <= 1)) throw new Error("invalid_point");
    await commands.control();
    await driver.page.locator(SURFACE).scrollIntoViewIfNeeded();
    const box = await driver.page.evaluate(
      ({ surface, x, y }) => {
        const container = document.querySelector(surface);
        const video = container.querySelector("video");
        let rect = video.getBoundingClientRect();
        const clip = container.getBoundingClientRect();
        const scale = Math.min(rect.width / video.videoWidth, rect.height / video.videoHeight);
        const targetX =
          rect.x + (rect.width - video.videoWidth * scale) / 2 + x * video.videoWidth * scale;
        const targetY =
          rect.y + (rect.height - video.videoHeight * scale) / 2 + y * video.videoHeight * scale;
        // Actual size scrolls the native frame; do not click the clipped portion
        // or normalize against the viewport rather than the received video.
        container.scrollLeft +=
          targetX - Math.max(clip.left + 8, Math.min(clip.right - 8, targetX));
        container.scrollTop += targetY - Math.max(clip.top + 8, Math.min(clip.bottom - 8, targetY));
        rect = video.getBoundingClientRect();
        return {
          x: rect.x,
          y: rect.y,
          width: rect.width,
          height: rect.height,
          videoWidth: video.videoWidth,
          videoHeight: video.videoHeight,
        };
      },
      { surface: SURFACE, x, y },
    );
    if (!box.videoWidth || !box.videoHeight) throw new Error("video_not_rendered");
    // object-contain letterboxes the frame inside the element.
    const scale = Math.min(box.width / box.videoWidth, box.height / box.videoHeight);
    const left = box.x + (box.width - box.videoWidth * scale) / 2;
    const top = box.y + (box.height - box.videoHeight * scale) / 2;
    await driver.page.mouse.click(
      left + x * box.videoWidth * scale,
      top + y * box.videoHeight * scale,
    );
    return {};
  },
  async type(args) {
    if (!/^[a-z0-9]{1,64}$/.test(args.text ?? "")) throw new Error("invalid_text");
    await ui.select("Keyboard mode", "Physical keys");
    await commands.control();
    await driver.page.locator(SURFACE).focus();
    const focused = await driver.page.evaluate(
      (surface) => document.activeElement === document.querySelector(surface),
      SURFACE,
    );
    if (!focused) throw new Error("remote_surface_not_focused");
    await driver.page.keyboard.type(args.text, { delay: 40 });
    if (args.enter) await driver.page.keyboard.press("Enter");
    return {};
  },
  async keys(args) {
    if (!["Control+c", "Control+v", "KeyY", "KeyZ"].includes(args.key))
      throw new Error("invalid_fixture_key");
    if (args.mode) await ui.select("Keyboard mode", args.mode);
    await commands.control();
    await driver.page.locator(SURFACE).focus();
    await driver.page.keyboard.press(args.key);
    return {};
  },
  async unicodeKey(args) {
    const code = { "€": "KeyE", я: "KeyZ" }[args.key];
    if (!code) throw new Error("invalid_fixture_unicode_key");
    await ui.select("Keyboard mode", "Text");
    await commands.control();
    await driver.page.locator(SURFACE).focus();
    // Playwright insertText does not emit keyboard events. CDP supplies a real
    // Chromium keyboard event with a physical code through production InputCapture,
    // not a DOM callback or a raw product data-channel frame.
    await driver.cdp.send("Input.dispatchKeyEvent", {
      type: "keyDown",
      key: args.key,
      code,
      text: args.key,
    });
    await driver.cdp.send("Input.dispatchKeyEvent", { type: "keyUp", key: args.key, code });
    return {};
  },
  async holdShift() {
    await ui.select("Keyboard mode", "Physical keys");
    await commands.control();
    await driver.page.locator(SURFACE).focus();
    await driver.page.keyboard.down("Shift");
    return {};
  },
  async releaseControl() {
    await ui.click({ role: "button", text: "Release control" });
    await ui.wait({ role: "button", text: "Take control" });
    // This local browser keyup occurs after control authority was released.
    await driver.page.keyboard.up("Shift");
    return {};
  },
  async refuse(args) {
    if (
      !["oversized", "read-denied", "ended", "policy", "permission"].includes(args.boundary) ||
      !commandURL ||
      !commandCSRF
    )
      throw new Error("invalid_refusal_probe");
    const sessionId = /\/assistance\/([0-9a-f-]{36})$/.exec(
      new URL(driver.page.url()).pathname,
    )?.[1];
    if (!sessionId) throw new Error("invalid_refusal_session");
    const actor = await commands.identity();
    // Adversarial RPC uses the creator's real browser cookie and observed CSRF
    // header, never an owner backdoor or a mocked result. Credentials stay local.
    const refusal = await driver.page.evaluate(
      async ({ url, csrf, sessionId, boundary }) => {
        const requestId = crypto.randomUUID();
        const command = {
          requestId,
          kind:
            boundary === "read-denied"
              ? "ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ"
              : "ASSISTANCE_COMMAND_KIND_CLIPBOARD_WRITE",
        };
        if (boundary !== "read-denied")
          command.text =
            boundary === "oversized" ? "a".repeat(16385) : "must-not-reach-ended-session";
        const response = await fetch(url, {
          method: "POST",
          credentials: "same-origin",
          cache: "no-store",
          headers: {
            "Content-Type": "application/json",
            "Connect-Protocol-Version": "1",
            "X-CSRF-Token": csrf,
          },
          body: JSON.stringify({ sessionId, command }),
        });
        const body = await response.json();
        const expectedCode =
          boundary === "oversized"
            ? "invalid_argument"
            : boundary === "permission"
              ? "not_found"
              : "failed_precondition";
        const expectedReason = {
          oversized: "invalid_assistance_command",
          "read-denied": "assistance_capability_not_granted",
          ended: "assistance_ended",
          policy: "assistance_ended",
          permission: "not_found",
        }[boundary];
        const reason = response.headers.get("Lindm-Reason");
        if (
          response.ok ||
          body.code !== expectedCode ||
          (boundary !== "oversized" && reason !== expectedReason)
        )
          throw new Error("authoritative_refusal_not_observed");
        return { boundary, requestId, code: body.code, reason, httpStatus: response.status };
      },
      { url: commandURL, csrf: commandCSRF, sessionId, boundary: args.boundary },
    );
    return { ...refusal, actor };
  },
  async clipboardSend(args) {
    if (!/^[a-f0-9]{24}$/.test(args.text ?? "")) throw new Error("invalid_fixture_nonce");
    await driver.page.evaluate((text) => navigator.clipboard.writeText(text), args.text);
    return completedCommand(() => ui.click({ role: "button", text: "Send clipboard" }));
  },
  async clipboardRead() {
    const result = await completedCommand(() =>
      ui.click({ role: "button", text: "Read clipboard" }),
    );
    await ui.click({ role: "button", text: "Copy clipboard" });
    return { ...result, text: await driver.page.evaluate(() => navigator.clipboard.readText()) };
  },
  async special() {
    await ui.select("Special keys", "Close window");
    return completedCommand(() => ui.click({ role: "button", text: "Send special keys" }));
  },
  async presentation(args) {
    if (!["Fit", "Actual size", "Full screen", "Exit full screen"].includes(args.label))
      throw new Error("invalid_presentation");
    await ui.click({ role: "button", text: args.label });
    if (args.label.includes("full screen") || args.label === "Full screen") {
      const wanted = args.label === "Full screen";
      await until(
        () =>
          driver.page.evaluate((value) => Boolean(document.fullscreenElement) === value, wanted),
        10_000,
        "fullscreen_state_timeout",
      );
    }
    if (args.label === "Full screen") await ui.select("Keyboard mode", "Physical keys");
    return { label: args.label };
  },
  // The Base UI select mounts its popup after the click resolves: reading the
  // options at once returned none (ubuntu24-tier1-25), and the Escape meant
  // to close it ran before it opened. Wait for the popup both ways.
  async displays() {
    await driver.page.getByRole("combobox", { name: "Select display", exact: true }).click();
    const listbox = driver.page.getByRole("listbox");
    await listbox.getByRole("option").first().waitFor({ state: "visible" });
    const labels = (await listbox.getByRole("option").allTextContents()).map((label) =>
      label.trim(),
    );
    await driver.page.keyboard.press("Escape");
    await listbox.waitFor({ state: "hidden" });
    return { labels };
  },
  async display(args) {
    const selected = await driver.page
      .getByRole("combobox", { name: "Select display", exact: true })
      .innerText();
    const before = await commands.marker({});
    if (selected.trim() === args.label.trim()) return before;
    const command = await completedCommand(() => ui.select("Select display", args.label));
    return { ...(await commands.marker({ notHead: before.head })), command };
  },
  async fixture(args) {
    if (!/^[a-f0-9]{24}$/.test(args.nonce ?? "")) throw new Error("invalid_fixture_nonce");
    fixtureNonce = args.nonce;
    return commands.marker();
  },
  async marker(args = {}) {
    return until(
      async () => {
        const marker = await nativeMarker();
        return marker && marker.head !== args.notHead ? marker : null;
      },
      30_000,
      "native_head_marker_timeout",
    );
  },
  async message(args) {
    if (!/^[a-f0-9]{24}$/.test(args.text ?? "")) throw new Error("invalid_fixture_message");
    await ui.fill({ label: "Message" }, args.text);
    return completedCommand(() => ui.click({ role: "button", text: "Send message" }));
  },
  async boundary(args = {}) {
    const labels = args.onlyDisplay
      ? ["Select display"]
      : ["Send clipboard", "Read clipboard", "Send special keys", "Select display", "Send message"];
    for (const label of labels) {
      const node = driver.page.getByRole(label === "Select display" ? "combobox" : "button", {
        name: label,
        exact: true,
      });
      if ((await node.count()) && (await node.isEnabled()))
        throw new Error("ungranted_capability_enabled");
    }
    const control = driver.page.getByRole("button", { name: /^(Take control|Release control)$/ });
    if (await control.count()) {
      if ((await control.getAttribute("aria-pressed")) !== null)
        throw new Error("control_action_exposed_as_toggle");
      if (await control.isDisabled()) {
        const explained = await control.evaluate((button) =>
          (button.getAttribute("aria-describedby") ?? "").split(/\s+/).some((id) => {
            const explanation = document.getElementById(id);
            return explanation?.innerText.trim() && explanation.getClientRects().length > 0;
          }),
        );
        if (!explained) throw new Error("disabled_control_reason_not_visible");
      }
    }
    return { noEnabledCapabilityActions: true };
  },
  async stop() {
    await ui.click({ role: "button", text: "Stop session" });
    return {};
  },
  async ended(args) {
    // The viewer states the end cause in the paragraph after its end heading;
    // a refused request reads "Why it couldn't start" (pop2404-assistance-dbg-01).
    const cause = await until(
      () =>
        driver.page.evaluate((headings) => {
          const heading = [...document.querySelectorAll("h2")].find((node) =>
            headings.includes(node.textContent.trim()),
          );
          return heading?.nextElementSibling?.innerText.trim() ?? "";
        }, END_HEADINGS),
      timeout(args),
      "console_end_cause_timeout",
    );
    return { cause };
  },
  async screenshot(args) {
    if (!/^[a-z0-9-]{1,80}\.png$/.test(args.name ?? "")) throw new Error("invalid_screenshot_name");
    const path = join(config.evidenceDirectory, args.name);
    await writePrivate(path, await driver.screenshot());
    return { path: args.name };
  },
  async leave(args) {
    if (!/^[0-9a-f-]{36}$/.test(args.deviceId ?? "")) throw new Error("invalid_device");
    await driver.goto(`${config.origin}/devices/${args.deviceId}`);
    return {};
  },
};

function failure(error) {
  return {
    code: /^[a-z][a-z0-9_]+$/.test(error?.message ?? "") ? error.message : "browser_command_failed",
    errorType: error?.name ?? "Error",
    ...(error?.observation ? { observation: error.observation } : {}),
  };
}

// A start that fails once Chromium has a page also names what the console
// showed, the last navigation and how its same-origin requests ended. The
// observation is collected from the page, never from the exception, and the
// runner's own credentials are scrubbed from it.
async function startFailure(error) {
  const result = startupFailure(error, startStage);
  if (!driver?.networkDiagnostics) return result;
  try {
    const page = await Promise.race([
      driver.page.evaluate(visibleOutcome),
      delay(5_000, undefined, { ref: false }).then(() => undefined),
    ]).catch(() => undefined);
    result.observation = startupObservation({ network: driver.networkDiagnostics(), page }, [
      config.password,
      config.enrollmentSecret,
    ]);
  } catch {
    result.observationUnavailable = true;
  }
  return result;
}

function reply(value) {
  process.stdout.write(JSON.stringify(value) + "\n");
}

starting("configuration");
try {
  if (process.argv.length !== 3) throw new Error("private_config_path_required");
  config = await readPrivateJSON(resolve(process.argv[2]));
  for (const key of ["origin", "username", "password", "enrollmentSecret", "evidenceDirectory"]) {
    if (typeof config[key] !== "string" || !config[key])
      throw new Error("required_configuration_missing");
  }
  const origin = new URL(config.origin);
  if (origin.protocol !== "https:" || origin.origin !== config.origin)
    throw new Error("https_origin_required");
  config.evidenceDirectory = resolve(config.evidenceDirectory);
  await privateDirectory(config.evidenceDirectory);
  config.actionTimeoutMs ??= 30_000;
  config.ignoreHTTPSErrors = true; // Owned fixture CA only; origin/CSRF checks stay intact.
  // A remote console behind an SSH -L forward reaches the relay only with TURN
  // over TCP; Chromium's own policy reproduces that without touching the page.
  if (config.turnTcpOnly !== undefined && typeof config.turnTcpOnly !== "boolean")
    throw new Error("invalid_turn_tcp_only");
  config.browserArgs = config.turnTcpOnly
    ? ["--force-webrtc-ip-handling-policy=disable_non_proxied_udp"]
    : [];
} catch (error) {
  await new Promise((done) =>
    process.stdout.write(
      JSON.stringify({ id: 0, ok: false, error: startupFailure(error, startStage) }) + "\n",
      done,
    ),
  );
  process.exit(1);
}

let closing = false;
const shutdown = async () => {
  if (closing) return;
  closing = true;
  try {
    if (driver) await driver.close();
  } finally {
    process.exit(0);
  }
};
process.once("SIGTERM", shutdown);
process.once("SIGINT", shutdown);

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of lines) {
  let request;
  try {
    request = JSON.parse(line);
  } catch {
    reply({ id: 0, ok: false, error: { code: "invalid_command" } });
    continue;
  }
  if (request.op === "close") break;
  const command = Object.hasOwn(commands, request.op) ? commands[request.op] : null;
  if (!command) {
    reply({ id: request.id, ok: false, error: { code: "unknown_command" } });
    continue;
  }
  try {
    reply({ id: request.id, ok: true, result: await command(request.args ?? {}) });
  } catch (error) {
    reply({
      id: request.id,
      ok: false,
      error: request.op === "start" ? await startFailure(error) : failure(error),
    });
  }
}
await shutdown();
