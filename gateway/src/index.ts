import { type Space, Spectrum, attachment } from "spectrum-ts";
import { imessage } from "spectrum-ts/providers/imessage";
import { terminal } from "spectrum-ts/providers/terminal";
import { createSeenSet } from "./dedupe";
import { loadRootEnv } from "./env";
import { type Outbox, type Policy, handleInbound } from "./handler";
import { toInbound } from "./inbound";
import { RateLimiter, limitFromEnv } from "./limiter";
import { chooseProviders } from "./providers";
import { createHasher, label, redact } from "./sender";

function outboxFor(space: Space): Outbox {
  return {
    sendText: async (text) => void (await space.send(text)),
    sendImage: async (bytes, name, mimeType) => void (await space.send(attachment(bytes, { name, mimeType }))),
  };
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
  for await (const [space, message] of app.messages) {
    if (message.direction === "outbound" || alreadySeen(message.id)) continue;
    // The number is hashed here and goes no further: only the hash and its last four digits are kept.
    const sender = hasher.identify(message.sender?.id ?? space.id ?? "");
    const policy: Policy = { sender, label: label(sender), limit: limiter.limit, take: () => limiter.take(sender.hash) };
    // Not awaited: one slow scan must not hold up the next message.
    handleInbound(toInbound(message.content), outboxFor(space), undefined, undefined, policy).catch((error) =>
      console.error("message failed:", redact(error instanceof Error ? error.message : String(error))),
    );
  }
}

main().catch((error) => {
  console.error(redact(error instanceof Error ? error.message : String(error)));
  process.exit(1);
});
