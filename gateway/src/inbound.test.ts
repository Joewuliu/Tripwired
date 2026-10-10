import assert from "node:assert/strict";
import { test } from "node:test";
import { toInbound } from "./inbound";

test("text becomes text", () => {
  assert.deepEqual(toInbound({ type: "text", text: "hi https://a.example" }), {
    kind: "text",
    text: "hi https://a.example",
  });
});

test("an image attachment becomes image", () => {
  assert.deepEqual(toInbound({ type: "attachment", mimeType: "image/jpeg" }), { kind: "image" });
});

test("other attachments, reactions and typing are ignored", () => {
  assert.deepEqual(toInbound({ type: "attachment", mimeType: "application/pdf" }), { kind: "ignore" });
  assert.deepEqual(toInbound({ type: "reaction" }), { kind: "ignore" });
  assert.deepEqual(toInbound({ type: "typing" }), { kind: "ignore" });
});
