/** Password hasher contract. Must be salt-deterministic, constant-time verify, and expose `needsRehash`. */
export namespace Hasher {
  /** A password hasher. */
  export type Me = {
    /** Names the algorithm and parameter set encoded into the hash. */
    readonly id: string
    /** Hashes with a fresh salt; the answer encodes the algorithm and parameters. */
    hash(plaintext: string): Promise<string>
    /** Whether `plaintext` matches, compared in constant time. */
    verify(plaintext: string, encoded: string): Promise<boolean>
    /** True when `encoded` came from an older or weaker parameter set than the current one. */
    needsRehash(encoded: string): boolean
  }
}
