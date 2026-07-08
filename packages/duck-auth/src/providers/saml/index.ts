/**
 * Wrapper over `@node-saml/node-saml` (lazy peerDep). Covers:
 *   - SP-initiated sign-in (HTTP-POST binding)
 *   - IdP-initiated SSO (unsolicited SAMLResponse)
 *   - SP metadata XML generation
 *   - Single Logout (SP- and IdP-initiated)
 *
 * Out of scope: artifact binding. Use node-saml directly if you need
 * a federal/military-grade artifact resolution profile.
 */

import type { Identity } from '~/core'
import { AuthError } from '~/core/errors'
import type { Provider } from '~/core/types/provider'

// 1 MiB cap on SAML response; larger XML inputs are adversarial.
const SAML_RESPONSE_MAX = 1_048_576
// SAML 2.0 binding spec caps RelayState at 80 bytes; 256 is generous
// to accommodate apps that pack a serialized state object.
const SAML_RELAY_STATE_MAX = 256
// DNS hostname max is 253 chars (RFC 1035).
const SAML_HOST_MAX = 253

export namespace AuthSamlProvider {
  /**
   * Subset of `@node-saml/node-saml` we depend on. Both v4 + v5 satisfy
   * this shape; consumers without the peerDep get AUTH/MISCONFIGURED
   * on first call.
   */
  export interface IClient {
    getAuthorizeUrlAsync(relayState: string, host: string, opts: Record<string, unknown>): Promise<string>
    validatePostResponseAsync(body: { SAMLResponse: string }): Promise<{
      profile: IProfile | null
      loggedOut: boolean
    }>
    /** Optional. node-saml exposes this synchronously. */
    generateServiceProviderMetadata?(decryptionCert?: string | null, signingCert?: string | null): string
    /** Optional. Builds an SP-initiated LogoutRequest URL (HTTP-Redirect binding). */
    getLogoutUrlAsync?(user: ILogoutUser, relayState: string, opts: Record<string, unknown>): Promise<string>
    /** Optional. Validates an IdP-sent LogoutRequest or LogoutResponse (Redirect binding). */
    validateRedirectAsync?(
      query: Record<string, string>,
      originalQuery: string,
    ): Promise<{ profile: IProfile | null; loggedOut: boolean }>
    /** Optional. Validates an IdP-sent LogoutRequest sent via HTTP-POST (rare). */
    validatePostRequestAsync?(body: { SAMLRequest: string }): Promise<{ profile: IProfile | null; loggedOut: boolean }>
    /** Optional. Builds a LogoutResponse URL for an IdP-initiated logout. */
    getLogoutResponseUrl?(
      user: ILogoutUser,
      relayState: string,
      opts: Record<string, unknown>,
      isError: boolean,
    ): string
  }

  /** Subset of node-saml's logout-user shape; sub = SAML nameID. */
  export interface ILogoutUser {
    nameID: string
    nameIDFormat?: string
    sessionIndex?: string
  }

  /**
   * Subset of node-saml's profile we extract. Library projects 30+
   * attributes onto the oauth-style `{ sub, email?, name? }` shape the
   * rest of the auth lib expects.
   */
  export interface IProfile {
    nameID: string
    nameIDFormat?: string
    email?: string
    attributes?: Record<string, string | string[]>
  }

  /** Config knobs for {@link authSamlProvider}. */
  export interface IOptions<Profile = unknown> {
    /**
     * Provider id reported back to consumers (e.g. `'okta'`,
     * `'azure-saml'`). Default `'saml'`.
     */
    providerId?: string
    /**
     * Pre-built `IClient` (the `@node-saml/node-saml` SAML class
     * instance). Required - SAML configuration is too varied to
     * express declaratively without depending on the library types.
     */
    client: IClient
    /**
     * Callback URL the IdP POSTs the SAMLResponse to. Must exactly
     * match the AssertionConsumerService URL registered with the IdP.
     */
    callbackUrl: string
    /** Translate the SAML profile into the app's `Profile` shape. */
    profileToIdentityProfile?: (profile: IProfile) => Profile
    /**
     * onSignIn hook fires after a successful SAMLResponse. Use to
     * just-in-time provision identities (lookup by `nameID` or
     * `email`, create if missing, return identityId).
     */
    onSignIn: (input: { profile: IProfile; tenantId?: string }) => Promise<{ identityId: string }>
  }

  /** Input to {@link authSamlProvider}.begin. */
  export interface IBeginInput {
    /** Caller-supplied relay state (CSRF guard); echoed back by IdP. */
    relayState: string
    /** Host the IdP redirects to (your app's origin). */
    host: string
  }

  /**
   * Input to {@link authSamlProvider}.complete. Covers both flows:
   *   - SP-initiated: the SAMLResponse references an InResponseTo we issued.
   *   - IdP-initiated: the SAMLResponse is unsolicited. Whether this is
   *     accepted is a node-saml config knob (`allowUnsolicited: true`).
   */
  export interface ICompleteInput {
    /** Raw SAMLResponse param from the IdP POST. */
    SAMLResponse: string
  }

  /** Input to {@link authSamlProvider}.slo.beginSp. */
  export interface ISloBeginSpInput {
    /** The SAML nameID of the user being logged out. */
    nameID: string
    nameIDFormat?: string
    sessionIndex?: string
    relayState: string
  }

  /** Input to {@link authSamlProvider}.slo.completeSp. */
  export interface ISloCompleteSpInput {
    /** IdP's response to our LogoutRequest (Redirect binding query params). */
    query: Record<string, string>
    /** The original query string captured at LogoutRequest send time, for sig verify. */
    originalQuery: string
  }

  /** Input to {@link authSamlProvider}.slo.completeIdp. */
  export interface ISloCompleteIdpInput {
    /** SAMLRequest param from the IdP-initiated logout (Redirect or POST). */
    query?: Record<string, string>
    originalQuery?: string
    SAMLRequest?: string
  }

  /** Result of {@link authSamlProvider}.slo.completeIdp. */
  export interface ISloCompleteIdpResult {
    /** SAML nameID of the user being logged out (the host should kill the matching session). */
    nameID: string | null
    /** A redirect URL to send the user to so the IdP gets a LogoutResponse. */
    redirectUrl: string
  }

  /** Config knobs for {@link authBuildSpMetadata}. */
  export interface IMetadataOptions {
    /** SP entityID. Must match the AudienceRestriction set at the IdP. */
    entityId: string
    /** AssertionConsumerService URL (where SAMLResponse is POSTed). */
    acsUrl: string
    /** Single Logout Service URL. Optional; omit if you don't support SLO. */
    sloUrl?: string
    /**
     * X.509 certificate the SP uses to sign AuthnRequests and validate
     * encrypted assertions. PEM body without `-----BEGIN-----` markers.
     */
    signingCert?: string
    /** Cert used to decrypt encrypted assertions. PEM body, no markers. */
    decryptionCert?: string
    /** NameID format the SP requires. Default: emailAddress. */
    nameIdFormat?: string
    /** Display name for the IdP's UI. */
    displayName?: string
    /** Want signed assertions? Default true. */
    wantAssertionsSigned?: boolean
    /** Want signed authn responses? Default true. */
    wantAuthnResponseSigned?: boolean
  }
}

/**
 * Build a SAML provider. Returns the standard `Provider.IProvider`
 * shape so it slots into AuthEngine.providers.register alongside the
 * authPassword / oauth providers.
 */
export function authSamlProvider<Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase>(
  opts: AuthSamlProvider.IOptions<Profile>,
): Provider.Me<AuthSamlProvider.IBeginInput, AuthSamlProvider.ICompleteInput, Profile> {
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
  const providerId = opts.providerId ?? 'saml'
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
      let validated: { profile: AuthSamlProvider.IProfile | null; loggedOut: boolean }
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

/**
 * Build the SAML SP metadata XML. Prefers the node-saml client's own
 * generator (which knows about every encoded extension) when present,
 * falls back to a minimal hand-rolled doc otherwise.
 *
 * Most IdPs will consume the XML at a stable URL like `/sso/saml/metadata`
 * and re-fetch on a TTL. Sign certificates rotate, so emit metadata
 * dynamically rather than checking it in.
 */
export function authBuildSpMetadata(opts: {
  client?: AuthSamlProvider.IClient
  metadata: AuthSamlProvider.IMetadataOptions
}): string {
  if (opts.client?.generateServiceProviderMetadata) {
    return opts.client.generateServiceProviderMetadata(
      opts.metadata.decryptionCert ?? null,
      opts.metadata.signingCert ?? null,
    )
  }
  return renderFallbackMetadata(opts.metadata)
}

/**
 * SLO controller. Three methods cover the three message flows:
 *
 *   1. `beginSp(input)` - we want to log the user out. Build a
 *      LogoutRequest URL and redirect the browser to the IdP's SLO
 *      endpoint.
 *   2. `completeSp(input)` - IdP replied to our LogoutRequest with a
 *      LogoutResponse. Validate the signature; the host then kills
 *      the local session.
 *   3. `completeIdp(input)` - IdP sent us a LogoutRequest (the user
 *      logged out elsewhere). Validate, kill the local session, and
 *      return a redirect URL the browser uses to POST a LogoutResponse
 *      back to the IdP.
 *
 * Every method requires the node-saml client to expose the matching
 * optional method on {@link AuthSamlProvider.IClient}. Missing methods
 * raise AUTH/MISCONFIGURED so misconfig fails fast at boot, not at
 * SLO time.
 */
export function authSamlSloController(opts: { providerId?: string; client: AuthSamlProvider.IClient }): {
  beginSp(input: AuthSamlProvider.ISloBeginSpInput): Promise<{ redirectUrl: string }>
  completeSp(input: AuthSamlProvider.ISloCompleteSpInput): Promise<{ nameID: string | null }>
  completeIdp(input: AuthSamlProvider.ISloCompleteIdpInput): Promise<AuthSamlProvider.ISloCompleteIdpResult>
} {
  if (!opts.client) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: 'samlSloController requires a pre-built `client` (@node-saml/node-saml SAML instance)',
    })
  }
  const providerId = opts.providerId ?? 'saml'
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
      const user: AuthSamlProvider.ILogoutUser = {
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
      let validated: { profile: AuthSamlProvider.IProfile | null; loggedOut: boolean }
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
      let validated: { profile: AuthSamlProvider.IProfile | null; loggedOut: boolean }
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
      const responseUser: AuthSamlProvider.ILogoutUser = nameID === null ? { nameID: '' } : { nameID }
      const redirectUrl = opts.client.getLogoutResponseUrl(responseUser, '', {}, false)
      return { nameID, redirectUrl }
    },
  }
}

function renderFallbackMetadata(m: AuthSamlProvider.IMetadataOptions): string {
  const wantAssertionsSigned = m.wantAssertionsSigned ?? true
  const wantAuthnResponseSigned = m.wantAuthnResponseSigned ?? true
  const nameIdFormat = m.nameIdFormat ?? 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
  const sslo = m.sloUrl
    ? `\n    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${escapeXml(m.sloUrl)}"/>`
    : ''
  const keyInfo = m.signingCert
    ? `
    <md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>${escapeXml(m.signingCert)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`
    : ''
  const encInfo = m.decryptionCert
    ? `
    <md:KeyDescriptor use="encryption"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>${escapeXml(m.decryptionCert)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`
    : ''
  return `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${escapeXml(m.entityId)}">
  <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="${wantAssertionsSigned}" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">${keyInfo}${encInfo}${sslo}
    <md:NameIDFormat>${escapeXml(nameIdFormat)}</md:NameIDFormat>
    <md:AssertionConsumerService isDefault="true" index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${escapeXml(m.acsUrl)}"/>
  </md:SPSSODescriptor>
${m.displayName ? `  <md:Organization><md:OrganizationName xml:lang="en">${escapeXml(m.displayName)}</md:OrganizationName><md:OrganizationDisplayName xml:lang="en">${escapeXml(m.displayName)}</md:OrganizationDisplayName><md:OrganizationURL xml:lang="en">${escapeXml(m.entityId)}</md:OrganizationURL></md:Organization>` : ''}
</md:EntityDescriptor>${wantAuthnResponseSigned ? '' : ''}`
}

function escapeXml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;')
}
