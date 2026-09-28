import {
  type AppAction,
  type AppResource,
  type AppRole,
  type AppScope,
  access,
  buildEngine as buildSharedEngine,
} from '@examples/duck-iam-shared/iam'
import { db } from '../db'

export type { AppAction, AppResource, AppRole, AppScope }
export { access }

export function buildEngine() {
  return buildSharedEngine(db)
}

let cachedEngine: ReturnType<typeof buildEngine> | undefined

// Memoized once per server process so hot-reloading route modules doesn't open a fresh engine
// (and pool) on every request.
export function getEngine(): ReturnType<typeof buildEngine> {
  cachedEngine ??= buildEngine()
  return cachedEngine
}
