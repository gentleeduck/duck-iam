import { AuthError } from '~/core/errors'
import { DEFAULT_SAML_CONFIG, SAML_NAME_ID_MAX, SAML_RELAY_STATE_MAX, SAML_RESPONSE_MAX } from '../saml.constants'
import type { Saml } from '../saml.types'

/** One method per logout message: the SP's LogoutRequest out, the IdP's LogoutResponse back, and an IdP's LogoutRequest in. */
export function samlSloController(opts: { providerId?: string; client: Saml.Client }): {
  /** The IdP URL an SP-initiated logout redirects to. */
  beginSp(input: Saml.SloBeginSpInput): Promise<{ redirectUrl: string }>
  /** Checks the IdP's LogoutResponse. */
  completeSp(input: Saml.SloCompleteSpInput): Promise<void>
  /** Checks an IdP's LogoutRequest; answers who to log out and where to respond. */
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
        input.nameID.length > SAML_NAME_ID_MAX ||
        input.nameID.includes('\r') ||
        input.nameID.includes('\n')
      ) {
        throw new AuthError('AUTH_INVALID_PARAMETERS', {
          detail: `slo.beginSp requires nameID (1-${SAML_NAME_ID_MAX} chars, no CR/LF)`,
        })
      }
      if (
        typeof input.relayState !== 'string' ||
        input.relayState.length === 0 ||
        input.relayState.length > SAML_RELAY_STATE_MAX ||
        input.relayState.includes('\r') ||
        input.relayState.includes('\n')
      ) {
        throw new AuthError('AUTH_INVALID_PARAMETERS', {
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
      const signed = redirectParams(input.originalQuery, 'SAMLResponse')
      if (!signed) {
        throw new AuthError('AUTH_PROVIDER_FAILED', {
          providerId,
          detail: 'invalid LogoutResponse query',
        })
      }
      let validated: { profile: Saml.Profile | null; loggedOut: boolean }
      try {
        validated = await opts.client.validateRedirectAsync(signed.query, signed.originalQuery)
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
    },

    async completeIdp(input) {
      if (!opts.client.getLogoutResponseUrlAsync) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: 'samlSloController.completeIdp: client does not implement getLogoutResponseUrlAsync',
        })
      }
      let validated: { profile: Saml.Profile | null; loggedOut: boolean }
      let relayState = ''
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
        relayState = input.RelayState ?? ''
        try {
          validated = await opts.client.validatePostRequestAsync({ SAMLRequest: input.SAMLRequest })
        } catch {
          throw new AuthError('AUTH_PROVIDER_FAILED', {
            providerId,
            detail: 'LogoutRequest validation failed',
          })
        }
      } else if (input.originalQuery !== undefined) {
        if (!opts.client.validateRedirectAsync) {
          throw new AuthError('AUTH_MISCONFIGURED', {
            detail: 'samlSloController.completeIdp: client does not implement validateRedirectAsync',
          })
        }
        const signed = redirectParams(input.originalQuery, 'SAMLRequest')
        if (!signed) {
          throw new AuthError('AUTH_PROVIDER_FAILED', {
            providerId,
            detail: 'invalid LogoutRequest query',
          })
        }
        relayState = signed.query.RelayState ?? ''
        try {
          validated = await opts.client.validateRedirectAsync(signed.query, signed.originalQuery)
        } catch {
          throw new AuthError('AUTH_PROVIDER_FAILED', {
            providerId,
            detail: 'LogoutRequest validation failed',
          })
        }
      } else {
        throw new AuthError('AUTH_INVALID_PARAMETERS', {
          detail: 'slo.completeIdp requires either { SAMLRequest } or { originalQuery }',
        })
      }
      const request = validated.profile
      if (!validated.loggedOut || !request) {
        throw new AuthError('AUTH_PROVIDER_FAILED', {
          providerId,
          detail: 'expected LogoutRequest; got sign-in assertion',
        })
      }
      // The request itself, for its `ID`: the response names it in `InResponseTo`. Success, since the host
      // kills the session before it sends the user on.
      const redirectUrl = await opts.client.getLogoutResponseUrlAsync(request, relayState, {}, true)
      return { nameID: request.nameID, redirectUrl }
    },
  }
}

/**
 * The Redirect binding's parameters, read off the raw query the signature covers. node-saml verifies a
 * signature only when one is present, and over the first token of the raw query naming each parameter,
 * while it decodes the message from a parsed copy; so each parameter is required once, the signature is
 * required, and both copies are built here from the same tokens.
 */
function redirectParams(
  raw: unknown,
  message: 'SAMLRequest' | 'SAMLResponse',
): { query: Record<string, string>; originalQuery: string } | null {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > SAML_RESPONSE_MAX) return null
  const query: Record<string, string> = {}
  const tokens: string[] = []
  for (const token of raw.split('&')) {
    const [entry] = new URLSearchParams(token)
    if (!entry) continue
    const [key, value] = entry
    if (key !== message && key !== 'RelayState' && key !== 'SigAlg' && key !== 'Signature') continue
    if (Object.hasOwn(query, key)) return null
    query[key] = value
    tokens.push(token)
  }
  if (!query[message] || !query.SigAlg || !query.Signature) return null
  return { originalQuery: tokens.join('&'), query }
}
