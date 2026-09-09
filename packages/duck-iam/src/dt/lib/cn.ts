/**
 * Joins class names, dropping anything falsy.
 *
 * A local four-line `cn` rather than the shared `@gentleduck/libs/cn`, which
 * every devtools file used to import. `@gentleduck/libs` is an *optional* peer
 * dependency of this package, so `import '@gentleduck/iam/dt'` threw
 * `ERR_MODULE_NOT_FOUND` for any consumer who had not also installed it - the
 * whole devtools surface, unreachable, over a string join.
 *
 * It deliberately does not merge conflicting Tailwind utilities the way the
 * shared helper does, because nothing here emits Tailwind utilities any more:
 * the classes are the `iam-dt-*` ones from `lib/styles.ts`, and two of those
 * never collide.
 */
export function cn(...parts: (string | false | null | undefined)[]): string {
  return parts.filter((part): part is string => typeof part === 'string' && part.length > 0).join(' ')
}
