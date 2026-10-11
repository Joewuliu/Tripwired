import { createHmac, randomBytes } from "node:crypto";

/**
 * Who a message came from, without the number. `hash` is a salted HMAC of the phone number or
 * address (stable for the same salt, useless without it), and `last4` is the only part of the
 * number kept, so a dashboard can show •••-4412. The number itself is never stored or logged.
 */
export interface SenderId {
  hash: string;
  last4: string | null;
}

export interface Hasher {
  identify(raw: string): SenderId;
}

const HASH_CHARS = 16;
const MIN_SALT_CHARS = 16;

/** Phones compare by digits (so "+1 (919) 555-4412" and "19195554412" are one sender); emails by lowercase. */
function normalize(raw: string): string {
  const trimmed = raw.trim();
  return trimmed.includes("@") ? trimmed.toLowerCase() : trimmed.replace(/\D/g, "");
}

/**
 * A hasher keyed by SENDER_SALT. Without a salt it makes a random one for this run and says so:
 * limits still work, but hashes change on restart, so set a salt on the VM.
 */
export function createHasher(salt: string | undefined, warn: (line: string) => void = console.warn): Hasher {
  let key = (salt ?? "").trim();
  if (!key) {
    key = randomBytes(32).toString("hex");
    warn("SENDER_SALT is not set: using a random salt for this run, so sender hashes change on restart.");
  } else if (key.length < MIN_SALT_CHARS) {
    warn(`SENDER_SALT is short (${key.length} characters): use at least ${MIN_SALT_CHARS}.`);
  }
  return {
    identify(raw) {
      const id = normalize(raw);
      const digits = id.replace(/\D/g, "");
      const isPhone = !id.includes("@") && digits.length >= 4;
      return {
        hash: createHmac("sha256", key).update(id).digest("hex").slice(0, HASH_CHARS),
        last4: isPhone ? digits.slice(-4) : null,
      };
    },
  };
}

/** What a dashboard shows for a sender: •••-4412, or just ••• when there is no number to take digits from. */
export function mask(sender: SenderId): string {
  return sender.last4 ? `•••-${sender.last4}` : "•••";
}

/** What a log line says about a sender: a short hash prefix and the mask. */
export function label(sender: SenderId): string {
  return `${sender.hash.slice(0, 8)} ${mask(sender)}`;
}

/** Last line of defence for anything printed from an error: no phone number or email survives. */
export function redact(text: string): string {
  return text
    .replace(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g, "[email]")
    .replace(/\+?\d[\d\s().-]{7,}\d/g, "[number]");
}
