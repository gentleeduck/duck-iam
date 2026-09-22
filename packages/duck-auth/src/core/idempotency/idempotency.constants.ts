import type { Idempotency } from './idempotency.types'

/** Defaults applied when `cfg.idempotency` omits a field. */
export const DEFAULT_IDEMPOTENCY_CONFIG: Idempotency.Cfg = {
  ttlMs: 24 * 60 * 60 * 1000,
  headerName: 'idempotency-key',
  pollTimeoutMs: 5_000,
}
