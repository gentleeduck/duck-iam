/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 *
 * Ready-to-render auth UI built on `@gentleduck/registry-ui`. Each
 * component takes callbacks, so the app wires them to its own auth
 * routes — no design work required.
 */

export { AuthLayout } from './auth-layout'
export { MfaTotpChallenge } from './mfa-totp-challenge'
export { ProvidersList } from './providers-list'
export { SessionBadge } from './session-badge'
export { SignInForm } from './sign-in-form'
export { SignOutButton } from './sign-out-button'
