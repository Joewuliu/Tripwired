/**
 * Remembers the last `limit` message ids. The returned function answers "have I seen this id?"
 * and records it, so a message redelivered after a reconnect is not scanned twice.
 */
export function createSeenSet(limit = 500): (id: string) => boolean {
  const seen = new Set<string>();
  return (id) => {
    if (seen.has(id)) return true;
    seen.add(id);
    if (seen.size > limit) seen.delete(seen.values().next().value as string);
    return false;
  };
}
