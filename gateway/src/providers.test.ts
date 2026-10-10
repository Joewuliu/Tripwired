import assert from "node:assert/strict";
import { test } from "node:test";
import { chooseProviders } from "./providers";

test("iMessage starts when credentials exist", () => {
  assert.deepEqual(chooseProviders({ hasCloudCredentials: true }), ["imessage"]);
});

test("nothing starts without credentials or the terminal flag", () => {
  assert.deepEqual(chooseProviders({ hasCloudCredentials: false }), []);
  assert.deepEqual(chooseProviders({ hasCloudCredentials: false, terminalFlag: "0" }), []);
});

test("the terminal chat is opt-in", () => {
  assert.deepEqual(chooseProviders({ hasCloudCredentials: false, terminalFlag: "1" }), ["terminal"]);
  assert.deepEqual(chooseProviders({ hasCloudCredentials: true, terminalFlag: "1" }), ["imessage", "terminal"]);
});
