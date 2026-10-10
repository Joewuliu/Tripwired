import type { Inbound } from "./handler";

/** The parts of a Spectrum message content the gateway looks at. */
interface Content {
  type: string;
  text?: unknown;
  mimeType?: unknown;
}

export function toInbound(content: Content): Inbound {
  switch (content.type) {
    case "text":
      return { kind: "text", text: String(content.text ?? "") };
    case "attachment":
      return String(content.mimeType ?? "").startsWith("image/") ? { kind: "image" } : { kind: "ignore" };
    default:
      return { kind: "ignore" }; // reactions, typing, voice and so on
  }
}
