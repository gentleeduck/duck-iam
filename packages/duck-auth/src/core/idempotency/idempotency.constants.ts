import type { Idempotency } from './idempotency.types'

export const DEFAULT_IDEMPOTENCY_CONFIG: Idempotency.Config = {
  ttlMs: 24 * 60 * 60 * 1000,
  headerName: 'idempotency-key',
  pollTimeoutMs: 5_000,
}
