import { AuthError } from '../errors'
import type { Identities } from './identities.types'

export const DEFAULT_IDENTITIES_CONFIG: Identities.Cfg = {
  softDeleteGracePeriodMs: 7 * 24 * 60 * 60 * 1000,
  profileMaxBytes: 16 * 1024,
}

/**
 * The one spelling an address is stored and looked up under. NFC as well as case, because `lower()`
 * folds case but not composition: 'cafe' + combining acute and the precomposed 'cafe' are two
 * different byte strings, so the unique index sees two addresses and a human sees one.
 */
export function canonicalEmail(raw: unknown): string | null {
  if (typeof raw !== 'string') return null
  const canonical = raw.trim().toLowerCase().normalize('NFC')
  return canonical.length > 0 ? canonical : null
}

/**
 * Every spelling a stored row may carry for one address, canonical first. A row written before
 * addresses were normalised still holds the bytes its client sent, so a lookup for the canonical
 * form alone would lock its owner out instead of finding them.
 */
export function emailSpellings(raw: unknown): readonly string[] | null {
  const canonical = canonicalEmail(raw)
  if (canonical === null) return null
  const asStored = typeof raw === 'string' ? raw.trim().toLowerCase() : canonical
  return asStored === canonical ? [canonical] : [canonical, asStored]
}

/**
 * What a store received, as a list, whichever of the two shapes {@link Identities.By} allows.
 *
 * An empty list is refused rather than passed on: a disjunction of no addresses is no condition at
 * all, so the query would match the first live row instead of none.
 */
export function toEmailList(email: string | readonly string[]): readonly string[] {
  const list = typeof email === 'string' ? [email] : email
  if (list.length === 0) {
    throw new AuthError('AUTH_INVALID_PARAMETERS', {
      detail: 'identities.find: email must name at least one spelling',
    })
  }
  return list
}

/**
 * The write with its address in NFC. Every dialect's unique index folds case in SQL but none of
 * them folds composition, so a decomposed spelling of an address a row already holds is a second
 * account. Case is left alone: `lower()` in the index already answers for it, and the local part
 * is the account holder's to spell.
 */
export function withNormalisedEmail<Write extends { profile?: unknown }>(write: Write): Write {
  const profile = write.profile
  if (typeof profile !== 'object' || profile === null || !('email' in profile)) return write
  const email = profile.email
  if (typeof email !== 'string') return write
  const normalised = email.normalize('NFC')
  return normalised === email ? write : { ...write, profile: { ...profile, email: normalised } }
}
