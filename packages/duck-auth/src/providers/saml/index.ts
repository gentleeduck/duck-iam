/**
 * @packageDocumentation
 * SAML 2.0 Service Provider. Wraps `@node-saml/node-saml` (lazy
 * peerDep) for the SP-initiated browser SSO profile: begin -> redirect
 * to IdP SSO endpoint with SAMLRequest, complete -> validate the
 * SAMLResponse POSTed to the AssertionConsumerService, extract the
 * subject + attributes, emit a startSession intent.
 *
 * Why lazy peerDep: SAML XML parsing + signature verification is
 * heavyweight (~2 MB after node_modules); apps that do not offer
 * enterprise SSO should not pay for it.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { AuthErrorObject } from '../../core/errors'
import type { Provider } from '../../core/types/provider'

/**
 * Subset of `@node-saml/node-saml` we depend on. Both v4 + v5 satisfy
 * this shape; consumers without the peerDep get AUTH/MISCONFIGURED on
 * first call.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface SamlClientLike {
  getAuthorizeUrlAsync(relayState: string, host: string, opts: Record<string, unknown>): Promise<string>
  validatePostResponseAsync(body: { SAMLResponse: string }): Promise<{
    profile: SamlProfile | null
    loggedOut: boolean
  }>
}

/**
 * Subset of node-saml's profile we extract. The actual shape has 30+
 * attributes; we project onto the OAuth-style `{ sub, email?, name? }`
 * shape the rest of the auth lib expects.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface SamlProfile {
  nameID: string
  nameIDFormat?: string
  email?: string
  attributes?: Record<string, string | string[]>
}

/**
 * Config knobs for the SAML SP provider.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface SamlProviderOptions<Profile = unknown> {
  /**
   * Provider id reported back to consumers (e.g. `'okta'`, `'azure-saml'`).
   * Default `'saml'`.
   */
  providerId?: string
  /**
   * Pre-built `SamlClientLike` (the `@node-saml/node-saml` SAML class
   * instance). Required - SAML configuration is too varied to express
   * declaratively without depending on the library types directly.
   */
  client: SamlClientLike
  /**
   * Callback URL the IdP POSTs the SAMLResponse to. Must exactly match
   * the AssertionConsumerService URL registered with the IdP.
   */
  callbackUrl: string
  /**
   * Translate the SAML profile into the app's `Profile` shape. Default
   * uses `{ email, name }` when present.
   */
  profileToIdentityProfile?: (profile: SamlProfile) => Profile
  /**
   * onSignIn hook fires after a successful SAMLResponse. Use to
   * just-in-time-provision identities (lookup by `nameID` or
   * `email`, create if missing, return identityId).
   */
  onSignIn: (input: { profile: SamlProfile; tenantId?: string }) => Promise<{ identityId: string }>
}

export interface SamlBeginInput {
  /** Caller-supplied relay state (CSRF guard); echoed back unmodified by IdP. */
  relayState: string
  /** Host the IdP redirects to (your app's origin). */
  host: string
}

export interface SamlCompleteInput {
  /** Raw SAMLResponse param from the IdP POST. */
  SAMLResponse: string
}

/**
 * Build a SAML provider. Returns the standard `Provider.IProvider`
 * shape so it slots into AuthRoot.providers.register alongside the
 * password / OAuth providers.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function samlProvider<Profile = unknown>(
  opts: SamlProviderOptions<Profile>,
): Provider.IProvider<SamlBeginInput, SamlCompleteInput, Profile> {
  if (!opts.client) {
    throw new AuthErrorObject('AUTH/MISCONFIGURED', {
      detail: 'samlProvider requires a pre-built `client` (@node-saml/node-saml SAML instance)',
    })
  }
  if (!opts.callbackUrl) {
    throw new AuthErrorObject('AUTH/MISCONFIGURED', {
      detail: 'samlProvider requires `callbackUrl` (matches IdP AssertionConsumerService URL)',
    })
  }
  if (!opts.onSignIn) {
    throw new AuthErrorObject('AUTH/MISCONFIGURED', {
      detail: 'samlProvider requires `onSignIn` (just-in-time identity provisioning hook)',
    })
  }
  const providerId = opts.providerId ?? 'saml'
  return {
    id: providerId,
    kind: 'oauth',

    async begin(_ctx, input): Promise<Provider.Intent[]> {
      if (!input.relayState || !input.host) {
        throw new AuthErrorObject('AUTH/MISCONFIGURED', {
          detail: 'saml.begin requires relayState + host',
        })
      }
      const url = await opts.client.getAuthorizeUrlAsync(input.relayState, input.host, {})
      return [{ type: 'redirect', url, status: 302 }]
    },

    async complete(ctx, input): Promise<Provider.Intent[]> {
      if (!input.SAMLResponse) {
        throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
          providerId,
          detail: 'missing SAMLResponse',
        })
      }
      let validated: { profile: SamlProfile | null; loggedOut: boolean }
      try {
        validated = await opts.client.validatePostResponseAsync({
          SAMLResponse: input.SAMLResponse,
        })
      } catch (err) {
        throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
          providerId,
          detail: err instanceof Error ? err.message : String(err),
        })
      }
      if (validated.loggedOut || !validated.profile) {
        throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
          providerId,
          detail: 'IdP returned a logout response, not a sign-in',
        })
      }

      const { identityId } = await opts.onSignIn({
        profile: validated.profile,
        ...(ctx.tenant.tenantId !== undefined && { tenantId: ctx.tenant.tenantId }),
      })
      return [
        {
          type: 'startSession',
          identityId,
          factors: [{ method: 'oauth', completedAt: Date.now() }],
          aal: 2,
        },
      ]
    },
  }
}

/**
 * Namespace merge for the SAML provider surface.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace SamlProvider {
  /** Alias for `SamlProviderOptions`. */
  export type IOptions = SamlProviderOptions
  /** Alias for `SamlBeginInput`. */
  export type IBeginInput = SamlBeginInput
  /** Alias for `SamlCompleteInput`. */
  export type ICompleteInput = SamlCompleteInput
  /** Alias for `SamlProfile`. */
  export type IProfile = SamlProfile
  /** Alias for `SamlClientLike`. */
  export type IClient = SamlClientLike
}
