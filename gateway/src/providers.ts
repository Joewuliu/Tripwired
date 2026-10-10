export type ProviderName = "imessage" | "terminal";

export interface ProviderInputs {
  /** SPECTRUM_PROJECT_ID and SPECTRUM_PROJECT_SECRET are both set. */
  hasCloudCredentials: boolean;
  /** TRIPWIRE_TERMINAL: "1" also starts the terminal chat (it downloads its own UI binary on first use). */
  terminalFlag?: string;
}

/** iMessage whenever the credentials exist; the terminal chat only when asked for. */
export function chooseProviders({ hasCloudCredentials, terminalFlag }: ProviderInputs): ProviderName[] {
  const names: ProviderName[] = [];
  if (hasCloudCredentials) names.push("imessage");
  if (terminalFlag === "1") names.push("terminal");
  return names;
}
