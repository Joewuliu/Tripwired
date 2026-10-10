import { type Space, Spectrum, attachment } from "spectrum-ts";
import { terminal } from "spectrum-ts/providers/terminal";
import { loadRootEnv } from "./env";
import { type Outbox, handleInbound } from "./handler";
import { toInbound } from "./inbound";

function outboxFor(space: Space): Outbox {
  return {
    sendText: async (text) => void (await space.send(text)),
    sendImage: async (bytes, name, mimeType) => void (await space.send(attachment(bytes, { name, mimeType }))),
  };
}

async function main(): Promise<void> {
  loadRootEnv();
  const app = await Spectrum({ providers: [terminal.config()] });
  console.log("Tripwire gateway up. Provider: terminal");

  for await (const [space, message] of app.messages) {
    if (message.direction === "outbound") continue;
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
