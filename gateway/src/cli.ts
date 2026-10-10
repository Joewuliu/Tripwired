// npm run check -- "text or link"
// Runs one message through the same handler the chat uses, printing what would be sent.
// Needs the analyzer running (ANALYZER_URL, default http://127.0.0.1:8001); needs no chat provider.
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { loadRootEnv } from "./env";
import { type Outbox, handleInbound } from "./handler";

const SAVE_DIR = resolve(import.meta.dirname, "../../data/gateway-out");

const out: Outbox = {
  async sendText(text) {
    console.log(`\n[text]\n${text}`);
  },
  async sendImage(bytes, name) {
    await mkdir(SAVE_DIR, { recursive: true });
    const path = resolve(SAVE_DIR, name);
    await writeFile(path, bytes);
    console.log(`\n[image] ${bytes.length} bytes saved to ${path}`);
  },
};

loadRootEnv();
const text = process.argv.slice(2).join(" ").trim();
if (!text) {
  console.error('usage: npm run check -- "text or link"');
  process.exit(1);
}
await handleInbound({ kind: "text", text }, out);
