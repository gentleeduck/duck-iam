/** Password hasher contract. Must be salt-deterministic, constant-time verify, and expose `needsRehash`. */
export namespace Hasher {
  export type Me = {
    /** Names the algorithm and parameter set encoded into the hash. */
    readonly id: string
    hash(plaintext: string): Promise<string>
    verify(plaintext: string, encoded: string): Promise<boolean>
    /** True when `encoded` came from an older or weaker parameter set than the current one. */
    needsRehash(encoded: string): boolean
  }
}
