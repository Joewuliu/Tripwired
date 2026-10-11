import { Spectrum, attachment } from "spectrum-ts";
import { imessage } from "spectrum-ts/providers/imessage";
import { terminal } from "spectrum-ts/providers/terminal";
import { resolve } from "node:path";
import { createSeenSet } from "./dedupe";
import { loadRootEnv } from "./env";
import { Family } from "./family";
import { fileAt } from "./familyStore";
import { type FamilyContext, type Policy, handleInbound } from "./handler";
import { toInbound } from "./inbound";
import { createOutbox } from "./outbox";
import { RateLimiter, limitFromEnv } from "./limiter";
import { chooseProviders } from "./providers";
import { createHasher, label, redact } from "./sender";

/** Family links live on the gateway's own data volume (TRIPWIRE_DATA_DIR, default gateway/data). */
function familyPath(): string {
  return resolve(process.env.TRIPWIRE_DATA_DIR || resolve(import.meta.dirname, "../data"), "family.json");
}

async function main(): Promise<void> {
  loadRootEnv();
  const projectId = process.env.SPECTRUM_PROJECT_ID;
  const projectSecret = process.env.SPECTRUM_PROJECT_SECRET;

  const names = chooseProviders({
    hasCloudCredentials: Boolean(projectId && projectSecret),
    terminalFlag: process.env.TRIPWIRE_TERMINAL,
  });
  if (names.length === 0) {
    console.error(
      "No chat provider to start. Set SPECTRUM_PROJECT_ID and SPECTRUM_PROJECT_SECRET in the repo-root .env " +
        "for iMessage. (TRIPWIRE_TERMINAL=1 adds the terminal chat.) To try the flow without chat: npm run check",
    );
    process.exit(1);
  }

  const providers = names.map((name) => (name === "imessage" ? imessage.config() : terminal.config()));
  const app =
    projectId && projectSecret
      ? await Spectrum({ projectId, projectSecret, providers })
      : await Spectrum({ providers });
  console.log(`Tripwire gateway up. Providers started: ${names.join(", ")}`);

  for (const signal of ["SIGINT", "SIGTERM"] as const) {
    process.once(signal, () => void app.stop().finally(() => process.exit(0)));
  }

  const alreadySeen = createSeenSet();
  const hasher = createHasher(process.env.SENDER_SALT);
  const limiter = new RateLimiter(limitFromEnv(process.env.TRIPWIRE_CHECKS_PER_HOUR));
  // Family mode needs to start conversations (an invite, an alert), which only iMessage can do here.
  const family = names.includes("imessage")
    ? new Family(
        fileAt(familyPath()),
        { sendTo: async (address, text) => void (await (await imessage(app).space.create(address)).send(text)) },
        (raw) => hasher.identify(raw),
      )
    : undefined;
  for await (const [space, message] of app.messages) {
    if (message.direction === "outbound" || alreadySeen(message.id)) continue;
    // The number is hashed here and goes no further: only the hash and its last four digits are kept.
    const sender = hasher.identify(message.sender?.id ?? space.id ?? "");
    const address = message.platform === "imessage" ? message.sender?.id : undefined;
    const familyContext: FamilyContext | undefined =
      family && address ? { service: family, me: { ...sender, address } } : undefined;
    const policy: Policy = { sender, label: label(sender), limit: limiter.limit, take: () => limiter.take(sender.hash) };
    // Not awaited: one slow scan must not hold up the next message.
    handleInbound(toInbound(message.content), createOutbox(space, message, (bytes, name, mimeType) => attachment(bytes, { name, mimeType })), undefined, undefined, policy, familyContext).catch((error) =>
      console.error("message failed:", redact(error instanceof Error ? error.message : String(error))),
    );
  }
}

main().catch((error) => {
  console.error(redact(error instanceof Error ? error.message : String(error)));
  process.exit(1);
});
