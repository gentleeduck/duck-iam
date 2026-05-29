/**
 * Password hasher contract. Implementations must be:
 *   - deterministic only when given the same salt
 *   - constant-time on verify
 *   - able to detect when their own parameters were outgrown
 *     (`needsRehash`) so a slow upgrade path can rotate hashes in place
 *
 * v0.1 ships scrypt (Node built-in, zero deps); v1.0 swaps in Argon2id
 * via `@node-rs/argon2` as the default with scrypt remaining as a fallback
 * for environments without WASM/native modules.
 */
export namespace Hasher {
  export interface IHasher {
    /** Identifier for the algorithm + parameter set encoded into the hash. */
    readonly id: string
    hash(plaintext: string): Promise<string>
    verify(plaintext: string, encoded: string): Promise<boolean>
    /** True when `encoded` was produced by an older/weaker parameter set than current. */
    needsRehash(encoded: string): boolean
  }
}
