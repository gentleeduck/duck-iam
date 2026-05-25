// Root barrel — intentionally narrow. Subpath imports (`@gentleduck/auth/core`,
// `@gentleduck/auth/adapters/memory`, etc.) are the primary surface to keep
// bundle size predictable. This entry re-exports the most common pairs only.
export { AuthRoot, type AuthRootConfig } from './core/auth'
export {
  type AuthError,
  type AuthErrorCode,
  AuthErrorObject,
} from './core/errors'
export {
  BearerTransport,
  CompositeTransport,
  CookieTransport,
} from './core/transport'
