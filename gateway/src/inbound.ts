import type { Inbound, Picture } from "./handler";

/** The parts of a Spectrum message content the gateway looks at. */
interface Content {
  type: string;
  text?: unknown;
  mimeType?: unknown;
  size?: unknown;
  read?: unknown;
  items?: { content: Content }[];
}

function isImage(content: Content): boolean {
  return content.type === "attachment" && String(content.mimeType ?? "").startsWith("image/");
}

/** A forward with several parts (text plus a picture) arrives as one group: read every part. */
function parts(content: Content): Content[] {
  return content.type === "group" && content.items ? content.items.flatMap((item) => parts(item.content)) : [content];
}

/** A picture whose bytes can be read later; the bytes are not fetched until they are needed. */
function toPicture(content: Content): Picture | null {
  if (!isImage(content) || typeof content.read !== "function") return null;
  const read = content.read as () => Promise<Buffer>;
  return {
    mimeType: String(content.mimeType),
    size: typeof content.size === "number" ? content.size : undefined,
    read: () => read.call(content),
  };
}

export function toInbound(content: Content): Inbound {
  const all = parts(content);
  const text = all
    .filter((part) => part.type === "text")
    .map((part) => String(part.text ?? ""))
    .join("\n")
    .trim();
  const hasImage = all.some(isImage);
  const pictures = all.map(toPicture).filter((picture): picture is Picture => picture !== null);
  const found = pictures.length > 0 ? { pictures } : {};
  if (text) return { kind: "text", text, hasImage, ...found };
  return hasImage ? { kind: "image", ...found } : { kind: "ignore" }; // reactions, typing, voice and so on
}
