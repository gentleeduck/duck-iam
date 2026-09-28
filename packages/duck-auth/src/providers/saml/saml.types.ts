/** SAML options, the node-saml surface it needs, and the replay store contract. */
export namespace Saml {
  /** The subset of `@node-saml/node-saml` this depends on, which its `SAML` instance satisfies. */
  export interface Client {
    /** The IdP URL an AuthnRequest redirects to. */
    getAuthorizeUrlAsync(relayState: string, host: string, opts: Record<string, unknown>): Promise<string>
    /** Validates a POSTed SAMLResponse and answers its profile. */
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
    /** Builds the LogoutResponse URL answering an IdP-initiated logout, `InResponseTo` the request's `ID`. */
    getLogoutResponseUrlAsync?(
      request: Profile,
      relayState: string,
      opts: Record<string, unknown>,
      success: boolean,
    ): Promise<string>
  }

  /** The part of node-saml's logout-user shape this uses; `sub` is the SAML nameID. */
  export interface LogoutUser {
    nameID: string
    nameIDFormat?: string
    sessionIndex?: string
  }

  /** The fields of node-saml's profile this reads, and all the hooks receive. */
  export interface Profile {
    nameID: string
    nameIDFormat?: string
    email?: string
    attributes?: Record<string, string | string[]>
    /** What the IdP says it did to authenticate. Decides the session's aal; see `mfaAuthnContexts`. */
    authnContext?: string
    /** The assertion's ID, which `replayStore` consumes once. */
    ID?: string
    sessionIndex?: string
    /** node-saml's parsed assertion. node-saml sets neither `ID` nor `authnContext` on a sign-in profile, and
     *  copies every attribute onto the profile's top level, so every field above but `email` and `attributes`
     *  is read from here when it is present. */
    getAssertion?(): unknown
  }

  /** The SAML client, and how an assertion maps to an identity. */
  export interface Options {
    /** Reported back to consumers, such as `'okta'` or `'azure-saml'`. Default `'saml'`. */
    providerId?: string
    /** A built `@node-saml/node-saml` instance: SAML config is too varied to express declaratively
     *  without depending on that library's types. */
    client: Client
    /** Where the IdP POSTs the SAMLResponse, matching the AssertionConsumerService URL registered with it.
     *  Checked against the client's own `callbackUrl` at construction, since the client is what validates
     *  `Destination` and `Recipient`, and the two disagreeing leaves this a presence test and nothing more. */
    callbackUrl: string
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
    /** Accepts responses with no replay protection at all. Default false: without a store one captured
     *  POST body mints a fresh session on every repeat, for as long as the assertion's own
     *  `NotOnOrAfter` window lasts, which node-saml's `acceptedClockSkewMs` widens. */
    allowReplay?: boolean
    /**
     * NameID formats the SP accepts. Defaults to the one `DEFAULT_SAML_CONFIG` asks for. A transient
     * nameID changes on every login, so provisioning keyed on it creates a new account each time.
     */
    allowedNameIdFormats?: readonly string[]
    /** AuthnContextClassRefs that earn aal 2. Defaults to `SAML_MFA_AUTHN_CONTEXTS`. */
    mfaAuthnContexts?: readonly string[]
    /** The attributes `onSignIn` sees; absent means every attribute the IdP sent. */
    allowedAttributes?: readonly string[]
    /** For both phases. One budget per tenant by default: coarse, but bounded. */
    limiterKey?: (ctx: { tenantId?: string }, phase: 'begin' | 'complete') => string
    /** Fires after a valid SAMLResponse. Where just-in-time provisioning goes: look the identity up by `nameID`
     *  or `email`, create it if missing, answer with its id. */
    onSignIn: (input: { profile: Profile; tenantId?: string }) => Promise<{ identityId: string }>
  }

  /** What starting a SAML sign-in takes. */
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

  /** What an SP-initiated logout takes. */
  export interface SloBeginSpInput {
    /** The nameID of the user being logged out. */
    nameID: string
    /** The nameID's format, as the assertion gave it. */
    nameIDFormat?: string
    /** The IdP session to end, from the assertion. */
    sessionIndex?: string
    /** Echoed back on the LogoutResponse. */
    relayState: string
  }

  /** The IdP's LogoutResponse, as it arrived. */
  export interface SloCompleteSpInput {
    /** The raw query string the IdP's LogoutResponse arrived with, undecoded and without the `?`: the
     *  signature covers it as sent. */
    originalQuery: string
  }

  /** An IdP's LogoutRequest, as it arrived. */
  export interface SloCompleteIdpInput {
    /** The raw query string of a Redirect-binding LogoutRequest, undecoded and without the `?`. Its
     *  `RelayState` is echoed back. */
    originalQuery?: string
    /** A POST-binding LogoutRequest. */
    SAMLRequest?: string
    /** The POST body's RelayState, echoed back as the SAML bindings require. */
    RelayState?: string
  }

  /** Who to log out, and the LogoutResponse URL to redirect to. */
  export interface SloCompleteIdpResult {
    /** The nameID of the user being logged out; the host kills the matching session. */
    nameID: string
    /** Send the user here, and the IdP gets its LogoutResponse. */
    redirectUrl: string
  }

  /** What the SP metadata XML is built from. */
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
