import { AuthError } from '../errors'
import type { Identities } from './identities.types'

export const DEFAULT_IDENTITIES_CONFIG: Identities.Cfg = {
  softDeleteGracePeriodMs: 7 * 24 * 60 * 60 * 1000,
  profileMaxBytes: 16 * 1024,
}

/** What `chk_auth_identities_email_length` and `chk_auth_identities_username_length` allow. Bounded to
 *  mysql's norm columns, so the row is refused alike on all three dialects. */
export const PROFILE_LOGIN_CAPS = { email: 320, username: 191 } as const

/** NFC as well as case: `lower()` folds case but not composition, so two spellings of one address would
 *  otherwise take two rows. */
export function canonicalEmail(raw: unknown): string | null {
  if (typeof raw !== 'string') return null
  const canonical = raw.trim().toLowerCase().normalize('NFC')
  return canonical.length > 0 ? canonical : null
}

/** Every spelling a stored row may carry for one address, canonical first. A row written before addresses
 *  were normalised still holds the bytes its client sent. */
export function emailSpellings(raw: unknown): readonly string[] | null {
  const canonical = canonicalEmail(raw)
  if (canonical === null) return null
  const asStored = typeof raw === 'string' ? raw.trim().toLowerCase() : canonical
  return asStored === canonical ? [canonical] : [canonical, asStored]
}

/** Every spelling a store matches one address against, never empty. A blank address answers `['']`, which
 *  matches nothing, since no dialect stores a blank one. */
export function toEmailList(email: string): readonly string[] {
  return emailSpellings(email) ?? ['']
}

/**
 * The write with its address in the one spelling {@link toEmailList} looks it up by, so a differently
 * cased, spaced or decomposed rendering of an address a row already holds is not a second account.
 *
 * SECURITY: case was left to the index on the grounds that it already folds it, and on sqlite it does not.
 * `lower()` there is ASCII-only - measured, `lower('JOSÉ@x.test')` answers `'JOSÉ@x.test'` - while pg,
 * mysql and `String.toLowerCase` all fold the whole of Unicode. sqlite's `create` leans on the unique
 * index alone and runs no check first, so an address with one uppercase non-ascii letter took a row the
 * index could not see was a duplicate, and `find` - which lowercases in JS before it asks - could not
 * match the row it had just written. Measured on the sqlite adapter: the account was `AUTH_IDENTITY_NOT_FOUND`
 * by the address it was created with, immediately after creating it, and a second account on that address
 * was accepted. Folding here rather than in the index makes the stored bytes the looked-up bytes, which no
 * dialect can then disagree about.
 */
export function withNormalisedEmail<Write extends { profile?: unknown }>(write: Write): Write {
  const profile = write.profile
  if (typeof profile !== 'object' || profile === null || !('email' in profile)) return write
  const email = profile.email
  if (typeof email !== 'string') return write
  // A blank address is left as it stands for `assertIdentityAllowed` to refuse by its own name.
  const normalised = canonicalEmail(email)
  return normalised === null || normalised === email ? write : { ...write, profile: { ...profile, email: normalised } }
}

/**
 * The identity rules every dialect carries as table constraints, so the unit tier is held to what
 * production enforces rather than to the in-process store's lack of a schema. Both logins must be a string
 * that says something and fits the column, and neither half of a provider link may be blank — a blank names
 * nobody, and the pair is what a lookup matches.
 *
 * An update is held to the same list, because `profile` is one column: a dialect writing a patch that omits
 * `email` drops the address, so a partial profile is refused there too.
 */
export function assertIdentityAllowed(write: {
  profile?: unknown
  providers?: readonly Identities.ProviderLinkInput[]
}): void {
  if (write.profile !== undefined) {
    for (const key of ['username', 'email'] as const) {
      const value = (write.profile as Record<string, unknown> | null)?.[key]
      if (typeof value !== 'string' || value === '') {
        throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: `profile.${key} must be a non-empty string` })
      }
      if (value.length > PROFILE_LOGIN_CAPS[key]) {
        throw new AuthError('AUTH_INVALID_PARAMETERS', {
          detail: `profile.${key} exceeds ${PROFILE_LOGIN_CAPS[key]} characters`,
        })
      }
    }
  }
  for (const link of write.providers ?? []) {
    if (link.providerId === '' || link.providerSub === '') {
      throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'provider link has a blank providerId or providerSub' })
    }
  }
}
