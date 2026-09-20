import { AuthError } from '~/core/errors'
import { DEFAULT_SAML_CONFIG, SAML_RELAY_STATE_MAX, SAML_RESPONSE_MAX } from '../saml.constants'
import type { Saml } from '../saml.types'

/** Three methods for the three message flows: */
export function samlSloController(opts: { providerId?: string; client: Saml.Client }): {
  beginSp(input: Saml.SloBeginSpInput): Promise<{ redirectUrl: string }>
  completeSp(input: Saml.SloCompleteSpInput): Promise<{ nameID: string | null }>
  completeIdp(input: Saml.SloCompleteIdpInput): Promise<Saml.SloCompleteIdpResult>
} {
  if (!opts.client) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: 'samlSloController requires a pre-built `client` (@node-saml/node-saml SAML instance)',
    })
  }
  const providerId = opts.providerId ?? DEFAULT_SAML_CONFIG.providerId
  return {
    async beginSp(input) {
      if (!opts.client.getLogoutUrlAsync) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: 'samlSloController.beginSp: client does not implement getLogoutUrlAsync',
        })
      }
      if (
        typeof input.nameID !== 'string' ||
        input.nameID.length === 0 ||
        input.nameID.length > 512 ||
        input.nameID.includes('\r') ||
        input.nameID.includes('\n')
      ) {
        throw new AuthError('AUTH_PROVIDER_FAILED', {
          providerId,
          detail: 'invalid nameID',
        })
      }
      if (
        typeof input.relayState !== 'string' ||
        input.relayState.length === 0 ||
        input.relayState.length > SAML_RELAY_STATE_MAX ||
        input.relayState.includes('\r') ||
        input.relayState.includes('\n')
      ) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: 'slo.beginSp requires relayState (1-256 chars, no CR/LF)',
        })
      }
      const user: Saml.LogoutUser = {
        nameID: input.nameID,
        ...(input.nameIDFormat !== undefined && { nameIDFormat: input.nameIDFormat }),
        ...(input.sessionIndex !== undefined && { sessionIndex: input.sessionIndex }),
      }
      const redirectUrl = await opts.client.getLogoutUrlAsync(user, input.relayState, {})
      return { redirectUrl }
    },

    async completeSp(input) {
      if (!opts.client.validateRedirectAsync) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: 'samlSloController.completeSp: client does not implement validateRedirectAsync',
        })
      }
      if (
        typeof input.originalQuery !== 'string' ||
        input.originalQuery.length === 0 ||
        input.originalQuery.length > SAML_RESPONSE_MAX
      ) {
        throw new AuthError('AUTH_PROVIDER_FAILED', {
          providerId,
          detail: 'invalid LogoutResponse query',
        })
      }
      let validated: { profile: Saml.Profile | null; loggedOut: boolean }
      try {
        validated = await opts.client.validateRedirectAsync(input.query, input.originalQuery)
      } catch {
        throw new AuthError('AUTH_PROVIDER_FAILED', {
          providerId,
          detail: 'LogoutResponse validation failed',
        })
      }
      if (!validated.loggedOut) {
        throw new AuthError('AUTH_PROVIDER_FAILED', {
          providerId,
          detail: 'expected LogoutResponse; got sign-in assertion',
        })
      }
      return { nameID: validated.profile?.nameID ?? null }
    },

    async completeIdp(input) {
      if (!opts.client.getLogoutResponseUrl) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: 'samlSloController.completeIdp: client does not implement getLogoutResponseUrl',
        })
      }
      let validated: { profile: Saml.Profile | null; loggedOut: boolean }
      if (input.SAMLRequest) {
        if (!opts.client.validatePostRequestAsync) {
          throw new AuthError('AUTH_MISCONFIGURED', {
            detail: 'samlSloController.completeIdp: client does not implement validatePostRequestAsync',
          })
        }
        if (input.SAMLRequest.length === 0 || input.SAMLRequest.length > SAML_RESPONSE_MAX) {
          throw new AuthError('AUTH_PROVIDER_FAILED', {
            providerId,
            detail: 'invalid SAMLRequest',
          })
        }
        try {
          validated = await opts.client.validatePostRequestAsync({ SAMLRequest: input.SAMLRequest })
        } catch {
          throw new AuthError('AUTH_PROVIDER_FAILED', {
            providerId,
            detail: 'LogoutRequest validation failed',
          })
        }
      } else if (input.query && input.originalQuery) {
        if (!opts.client.validateRedirectAsync) {
          throw new AuthError('AUTH_MISCONFIGURED', {
            detail: 'samlSloController.completeIdp: client does not implement validateRedirectAsync',
          })
        }
        if (input.originalQuery.length === 0 || input.originalQuery.length > SAML_RESPONSE_MAX) {
          throw new AuthError('AUTH_PROVIDER_FAILED', {
            providerId,
            detail: 'invalid LogoutRequest query',
          })
        }
        try {
          validated = await opts.client.validateRedirectAsync(input.query, input.originalQuery)
        } catch {
          throw new AuthError('AUTH_PROVIDER_FAILED', {
            providerId,
            detail: 'LogoutRequest validation failed',
          })
        }
      } else {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: 'slo.completeIdp requires either { SAMLRequest } or { query, originalQuery }',
        })
      }
      if (!validated.loggedOut) {
        throw new AuthError('AUTH_PROVIDER_FAILED', {
          providerId,
          detail: 'expected LogoutRequest; got sign-in assertion',
        })
      }
      const nameID = validated.profile?.nameID ?? null
      const responseUser: Saml.LogoutUser = nameID === null ? { nameID: '' } : { nameID }
      const redirectUrl = opts.client.getLogoutResponseUrl(responseUser, '', {}, false)
      return { nameID, redirectUrl }
    },
  }
}
