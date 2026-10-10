import { type Space, Spectrum, attachment } from "spectrum-ts";
import { imessage } from "spectrum-ts/providers/imessage";
import { terminal } from "spectrum-ts/providers/terminal";
import { createSeenSet } from "./dedupe";
import { loadRootEnv } from "./env";
import { type Outbox, handleInbound } from "./handler";
import { toInbound } from "./inbound";
import { chooseProviders } from "./providers";

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
  for await (const [space, message] of app.messages) {
    if (message.direction === "outbound" || alreadySeen(message.id)) continue;
    // Not awaited: one slow scan must not hold up the next message.
    handleInbound(toInbound(message.content), outboxFor(space)).catch((error) =>
      console.error("message failed:", error),
    );
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
