/**
 * Joins class names, dropping anything falsy.
 * NOTE: local, not `@gentleduck/libs/cn` - that is an optional peer, and `./dt` must load without it.
 */
export function cn(...parts: (string | false | null | undefined)[]): string {
  return parts.filter((part): part is string => typeof part === 'string' && part.length > 0).join(' ')
}
