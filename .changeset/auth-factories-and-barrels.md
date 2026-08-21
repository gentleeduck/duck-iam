---
'@gentleduck/auth': major
'@gentleduck/iam': minor
---

Export the factories, and finish the barrels.

The previous release gave every publicly constructed class a factory function, but
several were never exported, so `new` remained the only reachable spelling for
`AnomalyFacet`, `HijackFacet`, `WebhookDeliverer`, `MemoryPasskeyChallengeStore`,
`AuthMemoryDeviceFingerprintStore`, `DPoPVerifier`, the data-at-rest providers, the
password hashers, and the api-key / magic-link / passkey / saml / passwords impls.

The channels barrel exported one type and nothing else, so every channel had to be
imported by deep path. All six ship from `@gentleduck/auth/channels` now. The anomaly
barrel likewise omitted both detectors and the fingerprint store, which meant the
detectors could not be registered without reaching past it.

On the IAM side, `iamEngine` and `iamLRUCache` are exported alongside their classes.

BREAKING: three aliases in the `@gentleduck/auth` root now name the factory rather than
the class, so `new` on them stops compiling.

- `AuthBackupCodesFacet` is now `backupCodesFacet`; the class is `BackupCodesFacet`.
- `AuthInMemoryEvents` is now `inMemoryEvents`; the class is `InMemoryEvents`.

Both classes are exported under their own names, so `new BackupCodesFacet(...)` and
`new InMemoryEvents()` are the mechanical fix.
