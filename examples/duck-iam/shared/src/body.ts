function hasKey<K extends string>(obj: object, key: K): obj is Record<K, unknown> {
  return key in obj
}

function fieldOf(body: unknown, key: string): unknown {
  if (typeof body !== 'object' || body === null) return undefined
  if (!hasKey(body, key)) return undefined
  return body[key]
}

export function readString(body: unknown, key: string): string | undefined {
  const value = fieldOf(body, key)
  return typeof value === 'string' ? value : undefined
}

// `typeof value === 'number'` alone accepts NaN, Infinity, negatives and fractions — all of which
// either corrupt an `integer` column silently or crash the insert with an unhandled driver error.
// `min` pins the field's own business floor (0 for a price, 1 for a quantity) in one place.
export function readInt(body: unknown, key: string, min: number): number | undefined {
  const value = fieldOf(body, key)
  return typeof value === 'number' && Number.isInteger(value) && value >= min ? value : undefined
}

// Neither duck-auth nor Postgres (`users.email` is just `text ... unique`) checks that an email
// looks like one, so `readString` alone lets `signUp` create a real identity + company + user row
// from a value like `"not-an-email"`. Not RFC 5322 — just enough shape (one `@`, a label on each
// side, no whitespace) to reject garbage before it becomes a durable row.
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

export function readEmail(body: unknown, key: string): string | undefined {
  const value = fieldOf(body, key)
  return typeof value === 'string' && EMAIL_PATTERN.test(value) ? value : undefined
}

// `readString` treats `"   "` as present — non-empty per `typeof`/length, but meaningless as a
// display name. Every free-text label (a company's name, a user's name, a product's name) goes
// through this instead, so a caller can't create a row whose only visible identifier is
// whitespace, and so a name isn't stored with the leading/trailing padding it arrived with.
export function readTrimmedString(body: unknown, key: string): string | undefined {
  const value = fieldOf(body, key)
  if (typeof value !== 'string') return undefined
  const trimmed = value.trim()
  return trimmed.length > 0 ? trimmed : undefined
}
