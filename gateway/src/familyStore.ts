import { chmodSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

/**
 * Who protects whom, kept as one small JSON file on the gateway's own data volume.
 *
 * This is the only place Tripwire keeps a phone number: an alert or an invite cannot be sent
 * without one. It holds an address only for people in a link or a pending invite, and drops it when
 * the last of those ends. Everything else (logs, events, reports, the web pages) sees the hash and
 * the last four digits, as everywhere in the gateway.
 */
export interface Member {
  address: string; // where to send a message: the one raw value kept
  last4: string | null;
}

export interface Pair {
  guardian: string; // hash
  protected: string; // hash
}

export interface FamilyData {
  version: 1;
  people: Record<string, Member>; // by hash
  links: (Pair & { since: number })[];
  invites: (Pair & { expiresAt: number })[];
  cooldowns: (Pair & { until: number })[]; // this guardian may not invite this person again yet
  inviteTimes: Record<string, number[]>; // by guardian hash: when they sent invites, for the hourly limit
}

export function emptyFamily(): FamilyData {
  return { version: 1, people: {}, links: [], invites: [], cooldowns: [], inviteTimes: {} };
}

export interface Persistence {
  read(): string | null;
  write(text: string): void;
}

/** A file written whole or not at all, readable only by the gateway's own user. */
export function fileAt(path: string): Persistence {
  return {
    read() {
      try {
        return readFileSync(path, "utf8");
      } catch {
        return null;
      }
    },
    write(text) {
      mkdirSync(dirname(path), { recursive: true });
      const temp = `${path}.${process.pid}.tmp`;
      writeFileSync(temp, text, { mode: 0o600 });
      renameSync(temp, path);
      try {
        chmodSync(path, 0o600);
      } catch {
        // not every filesystem has modes; the volume is the gateway's alone either way
      }
    },
  };
}

function isPairList(value: unknown, extra: string): boolean {
  return (
    Array.isArray(value) &&
    value.every(
      (p) => p && typeof p.guardian === "string" && typeof p.protected === "string" && typeof p[extra] === "number",
    )
  );
}

/** The stored family data, or an empty one when there is none or it cannot be understood. */
export function loadFamily(persistence: Persistence, warn: (line: string) => void = console.warn): FamilyData {
  const text = persistence.read();
  if (text === null) return emptyFamily();
  try {
    const data = JSON.parse(text) as FamilyData;
    const ok =
      data?.version === 1 &&
      typeof data.people === "object" &&
      data.people !== null &&
      isPairList(data.links, "since") &&
      isPairList(data.invites, "expiresAt") &&
      isPairList(data.cooldowns, "until") &&
      typeof data.inviteTimes === "object" &&
      data.inviteTimes !== null;
    if (ok) return data;
  } catch {
    // fall through
  }
  warn("family store could not be read: starting with no links");
  return emptyFamily();
}

export function saveFamily(persistence: Persistence, data: FamilyData): void {
  persistence.write(JSON.stringify(data, null, 2));
}
