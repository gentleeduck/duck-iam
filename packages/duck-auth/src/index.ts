// Narrow root barrel; prefer subpath imports.
export { AuthEngine, authEngine } from './core/engine'
export { AuthError, rethrowAuthError, throwAuthError } from './core/errors'
export {
  BearerTransport as AuthBearerTransport,
  CompositeTransport as AuthCompositeTransport,
  CookieTransport as AuthCookieTransport,
} from './core/transport'
