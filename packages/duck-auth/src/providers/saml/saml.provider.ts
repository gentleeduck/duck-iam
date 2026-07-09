/**
 * Wrapper over `@node-saml/node-saml` (lazy peerDep). Covers:
 *   - SP-initiated sign-in (HTTP-POST binding)
 *   - IdP-initiated SSO (unsolicited SAMLResponse)
 *
 * SP metadata XML generation lives in `saml.metadata.ts`; Single Logout in
 * `saml.slo.ts`. Out of scope: artifact binding. Use node-saml directly if you
 * need a federal/military-grade artifact resolution profile.
 */

import type { Identity } from '~/core'
import { AuthError } from '~/core/errors'
import type { Provider } from '~/core/provider/provider.types'
import { DEFAULT_SAML_CONFIG, SAML_HOST_MAX, SAML_RELAY_STATE_MAX, SAML_RESPONSE_MAX } from './saml.constants'
import type { Saml } from './saml.types'

/**
 * Build a SAML provider. Returns the standard `Provider.Me` shape so it slots
 * into AuthEngine.providers.register alongside the password / oauth providers.
 */
export function saml<Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase>(
  opts: Saml.Options<Profile>,
): Provider.Me<Saml.BeginInput, Saml.CompleteInput, Profile> {
  if (!opts.client) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: 'samlProvider requires a pre-built `client` (@node-saml/node-saml SAML instance)',
    })
  }
  if (!opts.callbackUrl) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: 'samlProvider requires `callbackUrl` (matches IdP AssertionConsumerService URL)',
    })
  }
  if (!opts.onSignIn) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: 'samlProvider requires `onSignIn` (just-in-time identity provisioning hook)',
    })
  }
  const providerId = opts.providerId ?? DEFAULT_SAML_CONFIG.providerId
  return {
    id: providerId,
    kind: 'oauth',

    async begin(_ctx, input): Promise<Provider.Intent[]> {
      // Cap caller-supplied strings before they flow into IdP URL/headers.
      if (
        typeof input.relayState !== 'string' ||
        input.relayState.length === 0 ||
        input.relayState.length > SAML_RELAY_STATE_MAX ||
        input.relayState.includes('\r') ||
        input.relayState.includes('\n')
      ) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: 'saml.begin requires relayState (1-256 chars, no CR/LF)',
        })
      }
      if (
        typeof input.host !== 'string' ||
        input.host.length === 0 ||
        input.host.length > SAML_HOST_MAX ||
        input.host.includes('\r') ||
        input.host.includes('\n')
      ) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: 'saml.begin requires host (1-253 chars, no CR/LF)',
        })
      }
      const url = await opts.client.getAuthorizeUrlAsync(input.relayState, input.host, {})
      return [{ type: 'redirect', url, status: 302 }]
    },

    async complete(ctx, input): Promise<Provider.InternalIntent[]> {
      // cap SAMLResponse BEFORE handing it to
      // `validatePostResponseAsync` so adversarial multi-MB XML cannot
      // reach the parser. Real responses are 5-30 KiB; 1 MiB is generous.
      if (
        typeof input.SAMLResponse !== 'string' ||
        input.SAMLResponse.length === 0 ||
        input.SAMLResponse.length > SAML_RESPONSE_MAX
      ) {
        // Generic detail: do NOT echo size / type - the attacker
        // already knows what they sent, the legit caller bumped the cap.
        throw new AuthError('AUTH_PROVIDER_FAILED', {
          providerId,
          detail: 'invalid SAMLResponse',
        })
      }
      let validated: { profile: Saml.Profile | null; loggedOut: boolean }
      try {
        validated = await opts.client.validatePostResponseAsync({
          SAMLResponse: input.SAMLResponse,
        })
      } catch (err) {
        // Emit the real reason to operator audit; respond with a
        // generic detail so XML snippets do not reach the wire.
        const reason = err instanceof Error ? err.message : String(err)
        await ctx.events.emit('signin.failed', { providerId, reason })
        throw new AuthError('AUTH_PROVIDER_FAILED', {
          providerId,
          detail: 'SAMLResponse validation failed',
        })
      }
      if (validated.loggedOut || !validated.profile) {
        throw new AuthError('AUTH_PROVIDER_FAILED', {
          providerId,
          detail: 'IdP returned a logout response, not a sign-in',
        })
      }
      // Reject blank/oversize nameID; it drives JIT identity provisioning and
      // an empty value would collapse distinct accounts onto one row, while
      // an oversize one would bloat downstream identity-store writes.
      if (
        typeof validated.profile.nameID !== 'string' ||
        validated.profile.nameID.length === 0 ||
        validated.profile.nameID.length > 512
      ) {
        await ctx.events.emit('signin.failed', { providerId, reason: 'saml profile missing/invalid nameID' })
        throw new AuthError('AUTH_PROVIDER_FAILED', {
          providerId,
          detail: 'invalid SAML profile',
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
          factors: [{ method: 'oauth', completedAt: new Date() }],
          aal: 2,
        },
      ]
    },
  }
}
