/** A string field off an untrusted JSON body, `undefined` for anything else. */
export function readString(body: unknown, key: string): string | undefined {
  if (typeof body !== 'object' || body === null || !(key in body)) return undefined
  const value: unknown = Reflect.get(body, key)
  return typeof value === 'string' ? value : undefined
}
