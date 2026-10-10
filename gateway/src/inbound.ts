import type { Inbound } from "./handler";

/** The parts of a Spectrum message content the gateway looks at. */
interface Content {
  type: string;
  text?: unknown;
  mimeType?: unknown;
  items?: { content: Content }[];
}

function isImage(content: Content): boolean {
  return content.type === "attachment" && String(content.mimeType ?? "").startsWith("image/");
}

/** A forward with several parts (text plus a picture) arrives as one group: read every part. */
function parts(content: Content): Content[] {
  return content.type === "group" && content.items ? content.items.flatMap((item) => parts(item.content)) : [content];
}

export function toInbound(content: Content): Inbound {
  const all = parts(content);
  const text = all
    .filter((part) => part.type === "text")
    .map((part) => String(part.text ?? ""))
    .join("\n")
    .trim();
  const hasImage = all.some(isImage);
  if (text) return { kind: "text", text, hasImage };
  return hasImage ? { kind: "image" } : { kind: "ignore" }; // reactions, typing, voice and so on
}
