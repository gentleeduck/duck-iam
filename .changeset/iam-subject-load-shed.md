---
'@gentleduck/iam': minor
---

Add an optional `IConfig.maxConcurrentSubjectLoads` cap (default `0` = unbounded,
matching `adapterTimeoutMs`'s 0-disables convention) to bound the cold-flat herd
described in `SCALING.md` §8. `resolveSubject` rejects a *new* subject load once
`inFlight.subjects.size` hits the cap, before touching the adapter - fail-closed
load-shed, not a bounded queue, consistent with the engine's existing fail-closed
posture. The rejection is a plain `Error` whose message contains `"subject load
shed"`, so it surfaces through `can`/`check`/`authorize`'s existing fail-closed
`catch -> onError` path with no new wiring.

A call that hits the subject cache or joins an already-in-flight load for the same
subject never counts against the cap.
