/** A `strict()` that fails for a reason that is not a verdict, so `doctor` has to say which it was. */
export const auth = {
  strict(): void {
    throw new TypeError("Cannot read properties of undefined (reading 'compliance')")
  },
}
