/** Coerces an unknown catch value into a real `Error`, for callers that need one (an `onError` hook, `Error | null` state). */
export function toError(err: unknown): Error {
  return err instanceof Error ? err : new Error(String(err))
}
