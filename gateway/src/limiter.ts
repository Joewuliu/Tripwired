/** A sliding-window limit per sender hash, kept in memory (one gateway runs per Photon project). */
export class RateLimiter {
  private readonly hits = new Map<string, number[]>();

  constructor(
    readonly limit = 10,
    readonly windowMs = 60 * 60 * 1000,
    private readonly maxSenders = 10_000,
  ) {}

  /** Count one check for `key`. Returns null when allowed, or the milliseconds until it would be. */
  take(key: string, now = Date.now()): number | null {
    const recent = (this.hits.get(key) ?? []).filter((at) => now - at < this.windowMs);
    if (recent.length >= this.limit) {
      this.hits.set(key, recent);
      return Math.max(1000, this.windowMs - (now - recent[0]));
    }
    recent.push(now);
    this.hits.delete(key); // re-inserting keeps the map in least-recently-used order
    this.hits.set(key, recent);
    this.forgetOldest();
    return null;
  }

  private forgetOldest(): void {
    while (this.hits.size > this.maxSenders) {
      const oldest = this.hits.keys().next().value;
      if (oldest === undefined) return;
      this.hits.delete(oldest);
    }
  }
}

/** The checks an hour one sender gets: TRIPWIRE_CHECKS_PER_HOUR, 1 to 1000, default 10. */
export function limitFromEnv(value: string | undefined, fallback = 10): number {
  const parsed = Number.parseInt(value ?? "", 10);
  return Number.isInteger(parsed) && parsed >= 1 && parsed <= 1000 ? parsed : fallback;
}
