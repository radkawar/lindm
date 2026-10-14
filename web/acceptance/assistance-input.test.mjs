// SPDX-License-Identifier: Apache-2.0

// Runs production input logic with Node's built-in TypeScript stripping and test runner.
import assert from "node:assert/strict";
import test from "node:test";

import { InputCapture, printableKeysym } from "../src/features/assistance/input.ts";

function keyboardEvent(key, code, overrides = {}) {
  return {
    key,
    code,
    type: "keydown",
    isComposing: false,
    metaKey: false,
    ctrlKey: false,
    altKey: false,
    getModifierState: () => false,
    ...overrides,
  };
}

function capture() {
  const messages = [];
  const channel = { readyState: "open", send: (data) => messages.push(JSON.parse(data)) };
  return { input: new InputCapture(channel, "monitor-2", 7), messages };
}

test("printable conversion uses canonical legacy XKB across scripts", () => {
  const cases = [
    ["A", 0x0041],
    ["é", 0x00e9],
    ["Ą", 0x01a1],
    ["Ā", 0x03c0],
    ["ア", 0x04b1],
    ["ا", 0x05c7],
    ["я", 0x06d1],
    ["α", 0x07e1],
    ["א", 0x0ce0],
    ["ก", 0x0da1],
    ["ㄱ", 0x0ea1],
    ["Œ", 0x13bc],
    ["€", 0x20ac],
    ["日", 0x010065e5],
    ["🙂", 0x0101f642],
    // The old Korean_Won symbol is explicitly deprecated upstream.
    ["₩", 0x010020a9],
  ];
  for (const [key, expected] of cases) assert.equal(printableKeysym(key), expected, key);
});

test("LIMITED text never manufactures action, dead, modifier or nonprintable symbols", () => {
  for (const key of [
    "",
    "Enter",
    "Escape",
    "Delete",
    "F1",
    "Control",
    "AltGraph",
    "Dead",
    "Unidentified",
    "ab",
    "a\u0301",
    "\n",
    "\t",
    "\u007f",
    "\u0085",
    "\u00a0",
    "\u200b",
    "\u202e",
    "\ud800",
    "\udfff",
    "\ue000",
    "\u0378",
    "\uffff",
  ])
    assert.equal(printableKeysym(key), null, JSON.stringify(key));
  assert.equal(printableKeysym(" "), 0x20);
});

test("semantic input preserves exact canonical symbol on repeat and release with source fence", () => {
  const { input, messages } = capture();
  const down = keyboardEvent("€", "KeyE", {
    ctrlKey: true,
    altKey: true,
    getModifierState: (name) => name === "AltGraph",
  });
  assert.equal(input.key(down, "text"), true);
  assert.equal(input.key({ ...down, repeat: true }, "text"), true);
  // Layout/modifier state can change before keyup; release the held symbol.
  assert.equal(input.key(keyboardEvent("e", "KeyE", { type: "keyup" }), "text"), true);
  assert.deepEqual(messages, [
    { t: "keysym", keysym: 0x20ac, down: true, display: "monitor-2", generation: 7 },
    { t: "keysym", keysym: 0x20ac, down: true, display: "monitor-2", generation: 7 },
    { t: "keysym", keysym: 0x20ac, down: false, display: "monitor-2", generation: 7 },
  ]);
});

test("physical mode stays code-based and release-all remains generation-independent", () => {
  const { input, messages } = capture();
  assert.equal(input.key(keyboardEvent("z", "KeyY"), "physical"), true);
  input.releaseAll();
  assert.deepEqual(messages, [
    { t: "key", code: "KeyY", down: true, display: "monitor-2", generation: 7 },
    { t: "release" },
  ]);
  assert.equal(input.key(keyboardEvent("z", "KeyY", { type: "keyup" }), "physical"), false);
});

test("text mode rejects composition and shortcuts without sending operator input", () => {
  const { input, messages } = capture();
  for (const event of [
    keyboardEvent("a", "KeyA", { isComposing: true }),
    keyboardEvent("a", "KeyA", { ctrlKey: true }),
    keyboardEvent("a", "KeyA", { altKey: true }),
    keyboardEvent("a", "KeyA", { metaKey: true }),
    keyboardEvent("Dead", "Quote"),
    keyboardEvent("Enter", "Enter"),
  ])
    assert.equal(input.key(event, "text"), false);
  assert.deepEqual(messages, []);
});
