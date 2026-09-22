import type { Identities } from '~/core/identities'
import type { Sessions } from '~/core/sessions/sessions.types'
import type { VanillaClient } from './types'

/** Put the `Date`s back on a session envelope that arrived over HTTP. */
function asDate(value: unknown): unknown {
  if (typeof value !== 'string') return value
  const parsed = new Date(value)
  // Unparseable stays as it arrived, an Invalid Date passing `instanceof Date`
  // and compares `false` against everything, hiding a broken server.
  return Number.isFinite(parsed.getTime()) ? parsed : value
}

/**
 * Copy `row` with `keys` promoted to `Date`. The one assertion here, and the
 * narrowest place for it: a reviver's job is to produce a type its input is not.
 * `keys` tracks `Revived`'s `Date` fields by hand, and the date-fidelity tests
 * assert every one at runtime rather than trusting this signature.
 */
function withDates<Revived>(row: object, keys: readonly string[]): Revived {
  const out: Record<string, unknown> = { ...row }
  for (const key of keys) {
    if (key in out) out[key] = asDate(out[key])
  }
  return out as Revived
}

const SESSION_DATES = ['createdAt', 'updatedAt', 'rotatedAt', 'expiresAt', 'absoluteExpiresAt'] as const
const ACTING_AS_DATES = ['startedAt', 'expiresAt'] as const
const FACTOR_DATES = ['completedAt'] as const
const IDENTITY_DATES = ['createdAt', 'updatedAt', 'deletedAt'] as const
const PROVIDER_DATES = ['addedAt'] as const

/** Turns a session's serialised date strings back into `Date`s. */
export function reviveSession(session: VanillaClient.Serialized<Sessions.Public> | null): Sessions.Public | null {
  if (!session) return session
  // The array guards stay despite the types: the wire is a server's word, and a
  // `.map` on a non-array would throw out of a method that otherwise returns an
  // envelope for every failure.
  return withDates<Sessions.Public>(
    {
      ...session,
      actingAs: session.actingAs ? withDates<Sessions.ActingAs>(session.actingAs, ACTING_AS_DATES) : session.actingAs,
      factors: Array.isArray(session.factors)
        ? session.factors.map((factor) => withDates<Sessions.Factor>(factor, FACTOR_DATES))
        : session.factors,
    },
    SESSION_DATES,
  )
}

/** Turns an identity's serialised date strings back into `Date`s. */
export function reviveIdentity<Profile extends Identities.ProfileMetadataBase>(
  identity: VanillaClient.SerializedIdentity<Profile> | null,
): Identities.Me<Profile> | null {
  if (!identity) return identity
  return withDates<Identities.Me<Profile>>(
    {
      ...identity,
      providers: Array.isArray(identity.providers)
        ? identity.providers.map((provider) => withDates<Identities.ProviderLink>(provider, PROVIDER_DATES))
        : identity.providers,
    },
    IDENTITY_DATES,
  )
}

/** What `getSession` hands to callers and to `onChange` subscribers. */
export function reviveSessionResult<Profile extends Identities.ProfileMetadataBase>(
  data: VanillaClient.SerializedSessionResult<Profile>,
): VanillaClient.SessionResult<Profile> {
  return { identity: reviveIdentity(data.identity), session: reviveSession(data.session) }
}
