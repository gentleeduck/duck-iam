/** Default magic-link knobs; overridden per-call via `magicLink(opts)`. */
export const DEFAULT_MAGIC_LINK_CONFIG = {
  /** TTL of the magic-link token, ms. */
  ttlMs: 10 * 60 * 1000,
  /** Per-email rate-limit key prefix. */
  limiterKeyPrefix: 'magic-link:request:',
  /** Path the link lands on; token appended as `?token=`. */
  callbackPath: '/AUTH/magic-link/callback',
}
