import type { M2m } from './m2m.types'

export const DEFAULT_M2M_CONFIG: M2m.Config = {
  ttlMs: 60 * 60 * 1000,
  scopeMode: 'intersect',
}
