import { resolve } from "node:path";

/** Read the repo-root .env. Real environment variables win; no .env is fine. */
export function loadRootEnv(): void {
  try {
    process.loadEnvFile(resolve(import.meta.dirname, "../../.env"));
  } catch {
    // nothing to load
  }
}
