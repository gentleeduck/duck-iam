/** Real PII fields are tens to hundreds of bytes; this is generous, and it bounds the encrypt cycle. */
export const PLAINTEXT_MAX_LENGTH = 1_048_576

/** What encrypting the largest accepted plaintext produces: three UTF-8 bytes per UTF-16 unit, then
 *  base64url's four characters per three bytes, plus the envelope's other fields.
 *  WARN: not the plaintext cap, which let a value over ~786,000 characters encrypt and store, then fail
 *  every read of itself as oversize. */
export const CIPHERTEXT_MAX_LENGTH = PLAINTEXT_MAX_LENGTH * 4 + 4096
