/** Overridden per call through `magicLink(opts)`. */
export const DEFAULT_MAGIC_LINK_CONFIG = {
  /** Token TTL in ms. */
  ttlMs: 10 * 60 * 1000,
  /** Per-email rate-limit key prefix. */
  limiterKeyPrefix: 'magic-link:request:',
  /** Where the link lands; the token is appended as `?token=`. */
  callbackPath: '/auth/magic-link/callback',
}
