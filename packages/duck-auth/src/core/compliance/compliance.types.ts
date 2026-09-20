/** Regulatory presets and the closed set of clauses an adapter supplies evidence for. */
export namespace Compliance {
  export type Preset = 'gdpr' | 'hipaa' | 'soc2' | 'fips'

  /** A closed union rather than `string`, because the assertion is driven off this list: a preset naming
   *  something nothing can supply evidence for fails to build, rather than resolving to a requirement
   *  nothing ever looks at. */
  export type Check =
    | 'auditLogRetained7y'
    | 'baaCompliantChannel'
    | 'dataAtRest'
    | 'exportAvailable'
    | 'fipsValidatedHasher'
    | 'limiterRequired'
    | 'lockoutListener'
    | 'softDeleteEnabled'
    | 'webauthnAttestationDirect'

  /**
   * Evidence the deployment supplies. Some the engine sees for itself; the rest is an operator
   * attestation, because no code can tell whether a signed BAA exists.
   */
  export type Wired = Record<Check, boolean> & {
    /** Satisfies `requireChannelForReset`, which is a flag rather than a named check. */
    mailerChannel: boolean
  }

  export type Overrides = {
    passwords: { minLength: number }
    sessions: { ttlMs: number; absoluteTtlMs: number; freshnessMs: number }
    mfa: { backupCodeCount: number }
    apiKeys: { randomBytes: number }
    /** Names of strict() checks the preset insists on, sorted so two orderings resolve alike. */
    requiredStrictChecks: Check[]
    /** Minimum AAL enforced on every session created during signin. */
    minAal: 1 | 2 | 3
    /** When true, dataAtRest adapter required at boot. */
    requireDataAtRest: boolean
    /** When true, mailer / channel adapter required for any provider that needs it. */
    requireChannelForReset: boolean
  }
}
