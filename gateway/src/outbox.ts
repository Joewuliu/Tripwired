import type { Outbox } from "./handler";
import { redact } from "./sender";

/** The tapback put on a message we are about to check: a question mark, "looking into it". */
export const TAPBACK = "question";

/** The few things of a chat space and a message that the outbox uses. */
export interface ChatSpace {
  send(content: unknown): Promise<unknown>;
  startTyping(): Promise<void>;
  stopTyping(): Promise<void>;
}

export interface ChatMessage {
  react(reaction: string): Promise<unknown>;
}

const SIGNAL_TIMEOUT_MS = 5000;

/**
 * The reply channel for one message. `send` makes the content (text, or an attachment) for the
 * platform. The tapback and the typing indicator are best effort: neither is awaited, typing changes
 * are queued so a stop never overtakes its start, a call that never answers is given up on, and a
 * platform that rejects them costs one log line and nothing else.
 */
export function createOutbox(
  space: ChatSpace,
  message: ChatMessage,
  makeAttachment: (bytes: Buffer, name: string, mimeType: string) => unknown,
  timeoutMs = SIGNAL_TIMEOUT_MS,
): Outbox {
  let typingQueue: Promise<void> = Promise.resolve();
  const quiet = (what: string) => (error: unknown) =>
    console.warn(`${what} not shown:`, redact(error instanceof Error ? error.message : String(error)));
  const within = (work: Promise<unknown>) =>
    new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("timed out")), timeoutMs);
      work.then(
        () => (clearTimeout(timer), resolve()),
        (error) => (clearTimeout(timer), reject(error)),
      );
    });
  return {
    sendText: async (text) => void (await space.send(text)),
    sendImage: async (bytes, name, mimeType) => void (await space.send(makeAttachment(bytes, name, mimeType))),
    acknowledge: () => void Promise.resolve(message.react(TAPBACK)).catch(quiet("tapback")),
    typing: (on) => {
      typingQueue = typingQueue
        .then(() => within(on ? space.startTyping() : space.stopTyping()))
        .catch(quiet("typing indicator"));
    },
  };
}
