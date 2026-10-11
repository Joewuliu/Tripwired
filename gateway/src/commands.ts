/** The family-mode commands a person can text. A message is a command only when it is nothing else. */
export type Command =
  | { kind: "protect"; number: string | null } // number: digits with country code, or null if unreadable
  | { kind: "unprotect"; number: string | null }
  | { kind: "yes" }
  | { kind: "stop" }
  | { kind: "family" };

/**
 * A phone number as digits with its country code ("19195550142"), or null.
 *
 * Accepts the ways people type one: +1 919 555 0142, (919) 555-0142, 919.555.0142, 19195550142.
 * Ten digits are taken as a US or Canadian number. Anything with letters, or too short or long to be
 * a phone number, is refused rather than guessed at.
 */
export function parsePhone(text: string): string | null {
  const trimmed = text.trim();
  if (!/^\+?[\d\s().-]+$/.test(trimmed)) return null;
  const digits = trimmed.replace(/\D/g, "");
  if (trimmed.startsWith("+")) return digits.length >= 8 && digits.length <= 15 ? digits : null;
  if (digits.length === 10) return `1${digits}`;
  if (digits.length === 11 && digits.startsWith("1")) return digits;
  return null;
}

const WORD = /^(yes|stop|family)[.!]*$/i;
const WITH_NUMBER = /^(protect|unprotect)\b[\s:]*(.*)$/is;

/** The command in a message, or null when the message is something else (a link, a question). */
export function parseCommand(text: string): Command | null {
  const message = text.trim();
  const word = WORD.exec(message);
  if (word) return { kind: word[1].toLowerCase() as "yes" | "stop" | "family" };
  const numbered = WITH_NUMBER.exec(message);
  if (numbered) return { kind: numbered[1].toLowerCase() as "protect" | "unprotect", number: parsePhone(numbered[2]) };
  return null;
}
