import assert from "node:assert/strict";
import { test } from "node:test";
import { TAPBACK, createOutbox } from "./outbox";

function fakes(overrides: { start?: () => Promise<void>; stop?: () => Promise<void>; react?: () => Promise<unknown> } = {}) {
  const calls: string[] = [];
  const space = {
    send: async (content: unknown) => void calls.push(`send:${String(content)}`),
    startTyping: overrides.start ?? (async () => void calls.push("start")),
    stopTyping: overrides.stop ?? (async () => void calls.push("stop")),
  };
  const message = { react: overrides.react ?? (async (emoji: string) => void calls.push(`react:${emoji}`)) };
  return { calls, outbox: createOutbox(space, message, (_b, name) => `attachment ${name}`, 30) };
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 15));

test("the tapback is a question mark, 'looking into it', never a thumbs-up", async () => {
  assert.equal(TAPBACK, "question");
  const { calls, outbox } = fakes();
  outbox.acknowledge!();
  await settle();
  assert.deepEqual(calls, ["react:question"]);
});

test("typing starts and stops in order, however fast they are asked for", async () => {
  const { calls, outbox } = fakes();
  outbox.typing!(true);
  outbox.typing!(false);
  outbox.typing!(true);
  outbox.typing!(false);
  await settle();
  assert.deepEqual(calls, ["start", "stop", "start", "stop"]);
});

test("a rejected tapback or typing call is swallowed with one warning", async () => {
  const warnings: string[] = [];
  const original = console.warn;
  console.warn = (...a: unknown[]) => void warnings.push(a.map(String).join(" "));
  try {
    const { outbox } = fakes({
      react: async () => Promise.reject(new Error("unsupported for +1 919 555 0142")),
      start: async () => Promise.reject(new Error("no typing")),
    });
    outbox.acknowledge!();
    outbox.typing!(true);
    await settle();
  } finally {
    console.warn = original;
  }
  assert.equal(warnings.length, 2);
  assert.ok(!warnings.join(" ").includes("555"), "no number in the warning");
});

test("a typing call that never answers is given up on, so a later stop still goes through", async () => {
  const stops: string[] = [];
  const original = console.warn;
  console.warn = () => {};
  try {
    const { outbox, calls } = fakes({
      start: () => new Promise(() => {}),
      stop: async () => void stops.push("stop"),
    });
    outbox.typing!(true);
    outbox.typing!(false);
    await new Promise((resolve) => setTimeout(resolve, 80));
    assert.deepEqual(stops, ["stop"]);
    assert.deepEqual(calls, []);
  } finally {
    console.warn = original;
  }
});

test("sending is unchanged: text goes as text, a screenshot as an attachment", async () => {
  const { calls, outbox } = fakes();
  await outbox.sendText("hello");
  await outbox.sendImage(Buffer.from([1]), "shot.png", "image/png");
  assert.deepEqual(calls, ["send:hello", "send:attachment shot.png"]);
});
