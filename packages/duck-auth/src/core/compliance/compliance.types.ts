export namespace Compliance {
  export type Preset = 'gdpr' | 'hipaa' | 'soc2' | 'fips'

  export type Overrides = {
    passwords: { minLength: number }
    sessions: { ttlMs: number; absoluteTtlMs: number; freshnessMs: number }
    mfa: { backupCodeCount: number }
    apiKeys: { randomBytes: number }
    /** Names of strict() checks the preset insists on. */
    requiredStrictChecks: string[]
    /** Minimum AAL enforced on every session created during signin. */
    minAal: 1 | 2 | 3
    /** When true, dataAtRest adapter required at boot. */
    requireDataAtRest: boolean
    /** When true, mailer / channel adapter required for any provider that needs it. */
    requireChannelForReset: boolean
  }
}
