/** SAML options, the node-saml surface it needs, and the replay store contract. */
export namespace Saml {
  /** The subset of `@node-saml/node-saml` this depends on, satisfied by both v4 and v5. Without the
   *  peerDep the first call throws AUTH_MISCONFIGURED. */
  export interface Client {
    getAuthorizeUrlAsync(relayState: string, host: string, opts: Record<string, unknown>): Promise<string>
    validatePostResponseAsync(body: { SAMLResponse: string }): Promise<{
      profile: Profile | null
      loggedOut: boolean
    }>
    /** node-saml exposes this one synchronously. */
    generateServiceProviderMetadata?(decryptionCert?: string | null, signingCert?: string | null): string
    /** Builds an SP-initiated LogoutRequest URL over the HTTP-Redirect binding. */
    getLogoutUrlAsync?(user: LogoutUser, relayState: string, opts: Record<string, unknown>): Promise<string>
    /** Validates an IdP-sent LogoutRequest or LogoutResponse over the Redirect binding. */
    validateRedirectAsync?(
      query: Record<string, string>,
      originalQuery: string,
    ): Promise<{ profile: Profile | null; loggedOut: boolean }>
    /** Validates an IdP-sent LogoutRequest over HTTP-POST, which is rare. */
    validatePostRequestAsync?(body: { SAMLRequest: string }): Promise<{ profile: Profile | null; loggedOut: boolean }>
    /** Builds a LogoutResponse URL for an IdP-initiated logout. */
    getLogoutResponseUrl?(user: LogoutUser, relayState: string, opts: Record<string, unknown>, isError: boolean): string
  }

  /** The part of node-saml's logout-user shape this uses; `sub` is the SAML nameID. */
  export interface LogoutUser {
    nameID: string
    nameIDFormat?: string
    sessionIndex?: string
  }

  /** The subset of node-saml's profile extracted here, projecting its 30-odd attributes onto the oauth-style
   *  `{ sub, email?, name? }` the rest of the library expects. */
  export interface Profile {
    nameID: string
    nameIDFormat?: string
    email?: string
    attributes?: Record<string, string | string[]>
    /** What the IdP says it did to authenticate. Decides the session's aal; see `mfaAuthnContexts`. */
    authnContext?: string
    /** When the client surfaces one. `replayStore` consumes it once. */
    ID?: string
    sessionIndex?: string
  }

  export interface Options<AppProfile = unknown> {
    /** Reported back to consumers, such as `'okta'` or `'azure-saml'`. Default `'saml'`. */
    providerId?: string
    /** A built `@node-saml/node-saml` instance: SAML config is too varied to express declaratively
     *  without depending on that library's types. */
    client: Client
    /** Where the IdP POSTs the SAMLResponse, matching the AssertionConsumerService URL registered with it.
     *  Checked against the client's own `callbackUrl` at construction, since the client is what validates
     *  `Destination` and `Recipient`, and the two disagreeing leaves this a presence test and nothing more. */
    callbackUrl: string
    /** Translate the SAML profile into the app's `Profile` shape, or throw to refuse the sign-in. Runs before
     *  `onSignIn`, so a projection written to sanitise IdP attributes actually gets to. */
    profileToIdentityProfile?: (profile: Profile) => AppProfile
    /** Check the relay state the IdP echoed back against the one `begin` issued and the tenant consuming it.
     *  SECURITY: without it, an assertion the attacker obtained for their own account and POSTed into a victim's
     *  browser is indistinguishable from one the victim asked for, under any tenant the instance serves. */
    verifyRelayState?: (input: { relayState: string; tenantId?: string }) => Promise<boolean>
    /** Accepts a response carrying no relay state, the IdP-initiated flow. Default false, since nothing
     *  binds an unsolicited assertion to a request or a tenant. */
    allowUnsolicited?: boolean
    /** Consumes an assertion id exactly once, answering false when it has been seen.
     *  SECURITY: the only replay protection this wrapper requires. The client's InResponseTo cache is
     *  neither configured nor mandatory here, so without this one captured POST body mints a fresh session
     *  per repeat. */
    replayStore?: { consume: (assertionId: string) => Promise<boolean> }
    /**
     * NameID formats the SP accepts. Defaults to the one `DEFAULT_SAML_CONFIG` asks for. A transient
     * nameID changes on every login, so provisioning keyed on it creates a new account each time.
     */
    allowedNameIdFormats?: readonly string[]
    /** AuthnContextClassRefs that earn aal 2. Defaults to `SAML_MFA_AUTHN_CONTEXTS`. */
    mfaAuthnContexts?: readonly string[]
    /** Passed through to the hooks; absent means every attribute the IdP sent. */
    allowedAttributes?: readonly string[]
    /** For both phases. One budget per tenant by default: coarse, but bounded. */
    limiterKey?: (ctx: { tenantId?: string }, phase: 'begin' | 'complete') => string
    /** Fires after a valid SAMLResponse. Where just-in-time provisioning goes: look the identity up by `nameID`
     *  or `email`, create it if missing, answer with its id. */
    onSignIn: (input: { profile: Profile; tenantId?: string }) => Promise<{ identityId: string }>
  }

  export interface BeginInput {
    /** The CSRF guard, echoed back by the IdP. */
    relayState: string
    /** The app's own origin, which the IdP redirects to. */
    host: string
  }

  /** Covers both flows: SP-initiated, where the response references an InResponseTo this side issued, and
   *  IdP-initiated, where it is unsolicited and node-saml's `allowUnsolicited` decides whether it lands. */
  export interface CompleteInput {
    /** The raw SAMLResponse param off the IdP POST. */
    SAMLResponse: string
    /**
     * RelayState the IdP echoed back. Required unless `allowUnsolicited` is set: the value `begin`
     * issued as a CSRF guard had no counterpart on the way back.
     */
    relayState?: string
  }

  export interface SloBeginSpInput {
    /** The nameID of the user being logged out. */
    nameID: string
    nameIDFormat?: string
    sessionIndex?: string
    relayState: string
  }

  export interface SloCompleteSpInput {
    /** The IdP's answer to the LogoutRequest, as Redirect-binding query params. */
    query: Record<string, string>
    /** Captured when the LogoutRequest went out, for the signature check. */
    originalQuery: string
  }

  export interface SloCompleteIdpInput {
    /** Off the IdP-initiated logout, by Redirect or POST. */
    query?: Record<string, string>
    originalQuery?: string
    SAMLRequest?: string
  }

  export interface SloCompleteIdpResult {
    /** The nameID of the user being logged out; the host kills the matching session. */
    nameID: string | null
    /** Send the user here, and the IdP gets its LogoutResponse. */
    redirectUrl: string
  }

  export interface MetadataOptions {
    /** Must match the AudienceRestriction set at the IdP. */
    entityId: string
    /** The AssertionConsumerService URL, where the SAMLResponse is POSTed. */
    acsUrl: string
    /** Omit it when SLO is not supported. */
    sloUrl?: string
    /** Signs AuthnRequests and validates encrypted assertions. A PEM body with no `-----BEGIN-----`
     *  markers. */
    signingCert?: string
    /** Decrypts encrypted assertions. A PEM body, no markers. */
    decryptionCert?: string
    /** Default emailAddress. */
    nameIdFormat?: string
    /** Shown in the IdP's UI. */
    displayName?: string
    /** Rendered as the `WantAssertionsSigned` attribute. Default true. */
    wantAssertionsSigned?: boolean
    /** WARN: inert. `SPSSODescriptor` has no attribute for response signing, so this never reaches the
     *  generated XML and both values produce the same document; ask the IdP for a signed response in
     *  its own configuration. What enforces it at verification time is the node-saml client. */
    wantAuthnResponseSigned?: boolean
  }
}
