/** Password hasher contract. Must be salt-deterministic, constant-time verify, and expose `needsRehash`. */
export namespace AuthHasher {
  export interface IHasher {
    /** Identifier for the algorithm + parameter set encoded into the hash. */
    readonly id: string
    hash(plaintext: string): Promise<string>
    verify(plaintext: string, encoded: string): Promise<boolean>
    /** True when `encoded` was produced by an older/weaker parameter set than current. */
    needsRehash(encoded: string): boolean
  }
}
