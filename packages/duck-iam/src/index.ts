/**
 * Package entrypoint for `@gentleduck/iam`.
 *
 * Re-exports the core access-control engine and shared utilities. Adapters,
 * server middleware, client wrappers, invalidators, and observability live
 * behind subpath imports so consumers only pay for what they import:
 *
 *   import { MemoryAdapter } from '@gentleduck/iam/adapters/memory'
 *   import { adminRouter } from '@gentleduck/iam/server/express'
 *   import { createRedisInvalidator } from '@gentleduck/iam/invalidators/redis'
 */
export * from './core'
export { LRUCache } from './shared/cache'
export { buildPermissionKey, splitPermissionKey } from './shared/keys'
