/**
 * Storybook decorator. Wraps each story in
 * `<AuthProvider>` with either a mock `AuthVanillaClient.IClient` or a
 * real one pointed at a running backend. Mock is the default so
 * stories render without a server; opt in to live mode by passing
 * `live: true` (or a custom `baseUrl`).
 *
 * @example
 * ```ts
 * // .storybook/preview.ts
 * import { authWithStorybook } from '@gentleduck/auth/client/react/storybook'
 *
 * export const decorators = [
 *   authWithStorybook({
 *     identity: { id: 'demo', profile: { email: 'demo@example.com' } },
 *   }),
 * ]
 *
 * // Per-story live override:
 * export const Live = {
 *   parameters: { auth: { live: true } },
 * }
 * ```
 */

import { createElement, type JSX, type ReactNode } from 'react'
import type { AuthIdentity } from '../../../core/types/identity'
import type { AuthSession } from '../../../core/types/session'
import { authCreateClient, type AuthVanillaClient } from '../../vanilla'
import { AuthProvider } from '../index'

/** Default backend URL when a story opts into `live: true` without a custom `baseUrl`. */
export const AUTH_DEFAULT_LIVE_BASE_URL = 'http://localhost:8787/auth'

/**
 * Build a fake `AuthVanillaClient.IClient<Profile>` from a `AuthStorybook.IState`.
 * Every RPC resolves immediately with the configured state; `onChange`
 * fires once on subscribe.
 */
export function authCreateMockClient<Profile = unknown>(
  state: AuthStorybook.IState<Profile>,
): AuthVanillaClient.IClient<Profile> {
  const result: AuthVanillaClient.ISessionResult<Profile> = {
    identity: (state.identity ?? null) as AuthVanillaClient.ISessionResult<Profile>['identity'],
    session: (state.session ?? null) as AuthVanillaClient.ISessionResult<Profile>['session'],
  }
  return {
    async beginProvider() {
      return { body: { mock: true } }
    },
    async getSession() {
      return result
    },
    onChange(handler) {
      handler(result)
      return () => {}
    },
    async refresh() {
      return result
    },
    async signIn() {
      return { identity: result.identity, ok: true, session: result.session }
    },
    async signOut() {
      return { ok: true }
    },
  }
}

/**
 * Storybook decorator factory. Wraps the story in `<AuthProvider>`.
 * By default builds a mock client from `defaults`; passing
 * `live: true` (top-level or via `parameters.auth.live`) swaps in
 * `authCreateClient({ baseUrl })` so the story hits a real backend
 * with credentials.
 */
export function authWithStorybook<Profile = unknown>(defaults: AuthStorybook.IState<Profile> = {}) {
  return function authDecorator(
    Story: () => ReactNode,
    context?: { parameters?: { auth?: Partial<AuthStorybook.IState<Profile>> } },
  ): JSX.Element {
    const state: AuthStorybook.IState<Profile> = {
      ...defaults,
      ...(context?.parameters?.auth ?? {}),
    }
    const live = state.live === true
    const baseUrl = state.baseUrl ?? AUTH_DEFAULT_LIVE_BASE_URL
    const client = live
      ? authCreateClient<Profile>({
          baseUrl,
          // Always include the session cookie + CSRF cookie on cross-origin
          // requests so Storybook at :6006 can speak to the backend at :8787.
          fetch: (input, init) => fetch(input, { ...init, credentials: 'include' }),
        })
      : authCreateMockClient<Profile>(state)
    return createElement(
      AuthProvider,
      {
        baseUrl: live ? baseUrl : 'storybook://mock',
        client: client as unknown as AuthVanillaClient.IClient<unknown>,
        noInitialFetch: !live,
      },
      createElement(Story),
    ) as JSX.Element
  }
}

export namespace AuthStorybook {
  /**
   * The state the decorator should reflect. Both `identity` and
   * `session` default to `null` (guest). `status` is informational -
   * stories that branch on it should read `parameters.auth.status`.
   *
   * When `live: true`, the decorator ignores `identity`/`session` and
   * builds a real `AuthVanillaClient` against `baseUrl` (default
   * `http://localhost:8787/auth`, which matches the bundled
   * `apps/duck-auth-demo` server).
   */
  export interface IState<Profile = unknown> {
    status?: 'loading' | 'authed' | 'guest'
    identity?: Partial<AuthIdentity.IIdentity<Profile>> | null
    session?: Partial<AuthSession.ISession> | null
    /** Use a real client pointed at `baseUrl` instead of the mock. */
    live?: boolean
    /** Backend root for live mode. Defaults to `http://localhost:8787/auth`. */
    baseUrl?: string
  }
}
