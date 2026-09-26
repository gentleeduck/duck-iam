/** Coerces an unknown catch value into a real `Error`, for callers that need one (an `onError` hook, `Error | null` state). */
export function toError(err: unknown): Error {
  return err instanceof Error ? err : new Error(String(err))
}

/** A catch value's message, for callers that only log or report a string (never construct an `Error` just to read `.message`). */
export function toErrorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}
