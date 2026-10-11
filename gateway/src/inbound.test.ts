import assert from "node:assert/strict";
import { test } from "node:test";
import { toInbound } from "./inbound";

test("text becomes text", () => {
  assert.deepEqual(toInbound({ type: "text", text: "hi https://a.example" }), {
    kind: "text",
    text: "hi https://a.example",
    hasImage: false,
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

test("a forward with text and a picture is read as text that came with an image", () => {
  const group = {
    type: "group",
    items: [
      { content: { type: "text", text: "is this real? https://usps-track.top/x" } },
      { content: { type: "attachment", mimeType: "image/png" } },
    ],
  };
  assert.deepEqual(toInbound(group), {
    kind: "text",
    text: "is this real? https://usps-track.top/x",
    hasImage: true,
  });
});

test("a group of only pictures is an image", () => {
  const group = {
    type: "group",
    items: [{ content: { type: "attachment", mimeType: "image/png" } }, { content: { type: "attachment", mimeType: "image/jpeg" } }],
  };
  assert.deepEqual(toInbound(group), { kind: "image" });
});

test("several text parts are joined", () => {
  const group = { type: "group", items: [{ content: { type: "text", text: "one" } }, { content: { type: "text", text: "two" } }] };
  assert.deepEqual(toInbound(group), { kind: "text", text: "one\ntwo", hasImage: false });
});

test("blank text is ignored", () => {
  assert.deepEqual(toInbound({ type: "text", text: "   " }), { kind: "ignore" });
});

test("a picture that can be read is carried along, unread until needed", async () => {
  let reads = 0;
  const attachment = { type: "attachment", mimeType: "image/heic", size: 4, read: async () => (reads++, Buffer.from([1, 2, 3, 4])) };
  const inbound = toInbound({ type: "group", items: [{ content: { type: "text", text: "scan this" } }, { content: attachment }] });
  assert.equal(inbound.kind, "text");
  if (inbound.kind !== "text") return;
  assert.equal(inbound.pictures?.length, 1);
  assert.equal(reads, 0);
  assert.equal(inbound.pictures![0].mimeType, "image/heic");
  assert.equal(inbound.pictures![0].size, 4);
  assert.deepEqual([...(await inbound.pictures![0].read())], [1, 2, 3, 4]);
});
