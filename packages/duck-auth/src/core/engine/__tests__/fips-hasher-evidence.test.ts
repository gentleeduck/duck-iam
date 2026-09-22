/**
 * `fips` declares `fipsValidatedHasher`, and `CHECK_DEMANDS` spells out what it means: "Argon2id with FIPS
 * params". The package exports exactly those params as `ARGON2ID_COMPLIANCE`, and nothing applied them and
 * nothing compared against them, so the check was a boolean the operator typed. A fips deployment running
 * scrypt - or a hasher whose `verify` refuses everything - booted `strict()` clean.
 *
 * A foreign hasher still cannot be judged, and is not: FIPS 140 approves no Argon2 at all, so a host with a
 * genuinely validated implementation of its own has to be able to attest for it.
 */
import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { applyCompliancePreset } from '~/core/compliance'
import type { Compliance } from '~/core/compliance/compliance.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { mfaProvider } from '~/providers/mfa'
import { ARGON2ID_COMPLIANCE, argon2idHasher, passwords, scryptHasher } from '~/providers/passwords'
import type { Hasher } from '~/providers/passwords/hashers/hashers.types'
import { AuthEngine } from '../engine'

/** Publishes no opinion on the FIPS parameters, which is what a host's own implementation looks like. */
const foreignHasher: Hasher.Me = {
  hash: async () => '$foreign$x',
  id: 'foreign',
  needsRehash: () => false,
  verify: async () => false,
}

const ATTESTED: Partial<Compliance.Wired> = {
  dataAtRest: true,
  fipsValidatedHasher: true,
  mailerChannel: true,
  webauthnAttestationDirect: true,
}

function boot(hasher: Hasher.Me, wired: Partial<Compliance.Wired>, preset: Compliance.Preset = 'fips'): string {
  const adapter = new MemoryAdapter()
  const auth = new AuthEngine(
    applyCompliancePreset(
      {
        baseUrl: 'https://app.test',
        providers: [passwords({ hasher }), mfaProvider()],
        stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
        transport: new CookieTransport({ name: 'sid', secure: true }),
      } as never,
      preset,
    ) as never,
  )
  try {
    auth.strict({ compliance: wired, env: 'test' })
    return 'booted'
  } catch (err) {
    return (err as { meta: { detail: string } }).meta.detail
  }
}

describe('the FIPS hasher is evidenced, not attested, when the engine can see it', () => {
  it('refuses scrypt however loudly the operator attests', () => {
    expect(boot(scryptHasher({ N: 1 << 10, keylen: 32 }), ATTESTED)).toContain('Argon2id with FIPS params')
  })

  it('refuses Argon2id at the OWASP defaults, which is what `passwords()` picks on its own', () => {
    expect(boot(argon2idHasher(), ATTESTED)).toContain('fipsValidatedHasher')
  })

  it('boots on Argon2id at ARGON2ID_COMPLIANCE', () => {
    expect(boot(argon2idHasher(ARGON2ID_COMPLIANCE), ATTESTED)).toBe('booted')
  })

  it('boots on those params with no attestation at all, the evidence supplying the check', () => {
    const { fipsValidatedHasher: _omitted, ...rest } = ATTESTED
    expect(boot(argon2idHasher(ARGON2ID_COMPLIANCE), rest)).toBe('booted')
  })

  it('leaves a foreign hasher to the operator, who may hold a validated one of their own', () => {
    expect(boot(foreignHasher, ATTESTED)).toBe('booted')
  })

  it('and still refuses a foreign hasher nobody attested for', () => {
    const { fipsValidatedHasher: _omitted, ...rest } = ATTESTED
    expect(boot(foreignHasher, rest)).toContain('fipsValidatedHasher')
  })

  it('says nothing about the hasher under a preset that does not name the check', () => {
    // hipaa raises the AAL floor too, so this would be the place a stray `false` surfaced.
    expect(
      boot(
        scryptHasher({ N: 1 << 10, keylen: 32 }),
        { ...ATTESTED, auditLogRetained7y: true, baaCompliantChannel: true },
        'hipaa',
      ),
    ).toBe('booted')
  })
})

describe('what the hashers publish about those parameters', () => {
  it.each([
    ['ARGON2ID_COMPLIANCE', argon2idHasher(ARGON2ID_COMPLIANCE), true],
    ['the OWASP defaults', argon2idHasher(), false],
    ['stronger than FIPS on every axis', argon2idHasher({ ...ARGON2ID_COMPLIANCE, memoryCost: 131_072 }), true],
    ['FIPS but one notch short on memory', argon2idHasher({ ...ARGON2ID_COMPLIANCE, memoryCost: 65_535 }), false],
    ['FIPS but one notch short on parallelism', argon2idHasher({ ...ARGON2ID_COMPLIANCE, parallelism: 3 }), false],
    ['scrypt, at the highest cost Node will allocate', scryptHasher({ N: 1 << 17 }), false],
  ] as const)('%s -> %s', (_name, hasher, expected) => {
    expect(Reflect.get(hasher, '__fipsParams')).toBe(expected)
  })

  it('a foreign hasher publishes nothing, which is not the same as `false`', () => {
    expect(Reflect.get(foreignHasher, '__fipsParams')).toBeUndefined()
    expect(Reflect.get(passwords({ hasher: foreignHasher }), '__fipsValidatedHasher')).toBeUndefined()
    expect(Reflect.get(passwords({ hasher: scryptHasher() }), '__fipsValidatedHasher')).toBe(false)
  })
})
