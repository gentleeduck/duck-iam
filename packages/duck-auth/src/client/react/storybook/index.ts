/**
 * Storybook decorator. Wraps each story in
 * `<Provider>` with either a mock `VanillaClient.Client` or a
 * real one pointed at a running backend. Mock is the default so
 * stories render without a server; opt in to live mode by passing
 * `live: true` (or a custom `baseUrl`).
 *
 * @example
 * ```ts
 * // .storybook/preview.ts
 * import { authWithStorybook } from '@gentleduck/AUTH/client/react/storybook'
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
import { createAuthClient, type VanillaClient } from '~/client/vanilla'
import type { Identity } from '~/core/types/identity'
import type { Session } from '~/core/sessions/sessions.types'
import { Provider } from '../index'

/** Default backend URL when a story opts into `live: true` without a custom `baseUrl`. */
export const AUTH_DEFAULT_LIVE_BASE_URL = 'http://localhost:8787/auth'

/**
 * Build a fake `VanillaClient.Client<Profile>` from a `Storybook.State`.
 * Every RPC resolves immediately with the configured state; `onChange`
 * fires once on subscribe.
 */
export function authCreateMockClient<Profile extends Identity.ProfileMetadataBase>(
  state: Storybook.State<Profile>,
): VanillaClient.Client<Profile> {
  const result: VanillaClient.SessionResult<Profile> = {
    identity: (state.identity ?? null) as VanillaClient.SessionResult<Profile>['identity'],
    session: (state.session ?? null) as VanillaClient.SessionResult<Profile>['session'],
  }
  return {
    async beginProvider() {
      return { ok: true, code: 'AUTH_OK', data: { mock: true } }
    },
    async getSession() {
      return { ok: true, code: 'AUTH_OK', data: result }
    },
    onChange(handler) {
      handler(result)
      return () => {}
    },
    async refresh() {
      return { ok: true, code: 'AUTH_OK', data: result }
    },
    async signIn() {
      return { ok: true, code: 'AUTH_OK', data: result }
    },
    async signUp() {
      return { ok: true, code: 'AUTH_OK', data: { mock: true } }
    },
    async signOut() {
      return { ok: true, code: 'AUTH_OK', data: {} }
    },
  }
}

/**
 * Storybook decorator factory. Wraps the story in `<Provider>`.
 * By default builds a mock client from `defaults`; passing
 * `live: true` (top-level or via `parameters.auth.live`) swaps in
 * `authCreateClient({ baseUrl })` so the story hits a real backend
 * with credentials.
 */
export function authWithStorybook<Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase>(
  defaults: Storybook.State<Profile> = {},
) {
  return function authDecorator(
    Story: () => ReactNode,
    context?: { parameters?: { auth?: Partial<Storybook.State<Profile>> } },
  ): JSX.Element {
    const state: Storybook.State<Profile> = {
      ...defaults,
      ...(context?.parameters?.auth ?? {}),
    }
    const live = state.live === true
    const baseUrl = state.baseUrl ?? AUTH_DEFAULT_LIVE_BASE_URL
    const client = live
      ? createAuthClient<Profile>({
          baseUrl,
          // Always include the session cookie + CSRF cookie on cross-origin
          // requests so Storybook at :6006 can speak to the backend at :8787.
          fetch: (input: any, init: any) => fetch(input, { ...init, credentials: 'include' }),
        })
      : authCreateMockClient<Profile>(state)
    return createElement(
      Provider,
      {
        baseUrl: live ? baseUrl : 'storybook://mock',
        client: client,
        noInitialFetch: !live,
      },
      createElement(Story),
    )
  }
}

export namespace Storybook {
  /**
   * The state the decorator should reflect. Both `identity` and
   * `session` default to `null` (guest). `status` is informational -
   * stories that branch on it should read `parameters.auth.status`.
   *
   * When `live: true`, the decorator ignores `identity`/`session` and
   * builds a real `VanillaClient` against `baseUrl` (default
   * `http://localhost:8787/auth`, which matches the bundled
   * `apps/duck-auth-demo` server).
   */
  export type State<Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase> = {
    status?: 'loading' | 'authed' | 'guest'
    identity?: Partial<Identity.Me<Profile>> | null
    session?: Partial<Session.Me> | null
    /** Use a real client pointed at `baseUrl` instead of the mock. */
    live?: boolean
    /** Backend root for live mode. Defaults to `http://localhost:8787/auth`. */
    baseUrl?: string
  }
}
