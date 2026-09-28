# Anomaly detection

Whether a request that carries a valid session looks like the person the session was issued to. The
session is already authenticated by the time this module runs — its job is to score what is unusual
about the request around it, and to answer with one decision the caller branches on.

A detector produces signals; the facet combines them and returns a `deny`, a `step-up` or an `allow`.
Nothing here refuses anything by itself. `requestSecurity` is what turns a `deny` into a refused
request, and even then `step-up` is left to the host.

## The ladder

Scores are combined **noisy-or**, not summed:

```
combined = 1 - ∏(1 - score)
```

Two independent 0.5 signals come out at 0.75, three at 0.875 — more evidence always raises the score
and it saturates at 1 rather than running past it. A sum would put two 0.6 signals above `denyAt`
purely by addition, and the range every threshold is written against would stop meaning anything.

`_aggregate` then walks a fixed order, first match winning:

| | condition | decision |
| --- | --- | --- |
| 1 | an `allow` reaction on the signal | muted — it leaves the aggregate entirely |
| 2 | a non-finite score among what remains | `deny` |
| 3 | combined `>= denyAt` (0.95) | `deny` |
| 4 | a `deny` or `step-up` reaction on a remaining kind | that one, highest severity winning |
| 5 | combined `>= stepUpAt` (0.7) | `step-up` |
| 6 | — | `allow` |

Step 2 is why a detector returning `NaN` denies rather than passing: every comparison against `NaN` is
false, so without it the score would fall through all the way to the final `allow`.

`threshold` (0.7) is a separate dial and decides nothing. Every decision but `allow` fires the
`suspicious` event; an `allow` fires it too once it scores at least `threshold`, so an operator can
watch scores they do not act on yet.

## Reactions

`reactions` overrides the ladder per kind, nested detector id → kind → decision, with `'*'` as the
detector meaning "whoever emitted it":

```ts
reactions: {
  'new-device': { 'new-device': 'step-up' },
  '*': { 'impossible-travel': 'deny' },
}
```

`'allow'` mutes a signal — it is dropped before the score is computed, not scored and then overruled.
`'step-up'` and `'deny'` force at least that severity whatever it scored. A detector's own table wins
over the `'*'` one. The facet stamps each signal's detector id itself, so a plugin cannot claim an
override written for another detector.

Both levels are read with `Object.hasOwn`, so a detector id or kind spelling a prototype member is
answered no rather than handed `Object.prototype`'s. A misspelled decision is refused at construction:
left unchecked, `severity['denied']` is `undefined` and every comparison against it is false, so the
override an operator wrote applied to nothing and said nothing.

## Surface

**`anomaly.facet.ts`** — `AnomalyFacet`, the registry and the ladder. `createAuth` builds one and
exposes it as `auth.anomaly`.

- `register(detector)` — order does not affect the aggregate; an id already registered is refused.
- `unregister(id)` — `false` when nothing matched.
- `list()` — the registered ids.
- `evaluate({ session, identity, req })` — runs every detector and returns the `Anomaly.Result`, whose
  `admit()` hands the verdict to the `record` of each that answered.
- `decide(signals)` — the same ladder standalone, for re-deciding on signals you already hold.

**`anomaly.constants.ts`** — every tunable in the module, in four groups: the ladder
(`DEFAULT_ANOMALY_CONFIG`, `DETECTOR_TIMEOUT_MAX_MS`, `REACTION_ANY_DETECTOR`), the scoring maths
(`combineScores`, `clampScore`), and one group per detector. Neither detector holds a tunable of its
own, so the two defaults a deployment is most likely to want to change — 50 devices per identity, 900
km/h — are found in one file rather than by reading the implementations.

**`anomaly.types.ts`** — `Anomaly`, plus the two shipped detectors' config namespaces,
`AuthDeviceFingerprint` and `AuthImpossibleTravel`.

**`device-fingerprint.detector.ts`** — `deviceFingerprintDetector`, emitting `new-device` on first
sight of an (identity, fingerprint) pair. The default fingerprint is `sha256(ua | ipSubnet)` at /24
for IPv4 and /48 for IPv6, which tolerates roaming within an ISP while still separating networks.
`AuthMemoryDeviceFingerprintStore` is the only store this package ships, bounded per identity and
TTL'd at 90 days. It is process-local: a deployment running more than one process sees a first
sighting per process, so implement `AuthDeviceFingerprint.IStore` over shared storage there.

A device is remembered once the request is let through, and never for a `deny`, so a refused attempt is
still a new device on the retry and on any request racing it. Nor when the detector threw or overran: the
device was never scored. The actor wrappers call `admit()` after `onSession` passes, so a request the
verdict, the hijack policy or `onAnomaly` refuses remembers nothing. A route that refuses a `step-up`
itself, reading `anomaly.decision`, calls `store.forget(identityId, signal.evidence.fingerprint)`.

**`impossible-travel.detector.ts`** — `authImpossibleTravelDetector`, emitting `impossible-travel`
when the distance from the last known position over the elapsed time implies a speed above
`maxKmPerHour` (900 by default). It needs both ends: `getLastSeen`, which reads a position the host
records itself — nothing in this package stores one — and `req.geo`, which comes from `getCaller`.
Without the second it scores nothing on every request, since no request carries its own position.
Never record a position from a denied request: it moves "last seen" to the attacker, and their next
request is no travel at all.

## Wiring

Nothing is registered by default, and a facet with no detectors is skipped in full:

```ts
import { authMemoryDeviceFingerprintStore, deviceFingerprintDetector, sha256 } from '@gentleduck/auth/core'

auth.anomaly.register(
  deviceFingerprintDetector({ store: authMemoryDeviceFingerprintStore(), authSha256: sha256 }),
)
```

The detectors then run inside `resolveSession`, but only for a call that passes a `requestSnapshot` —
they have nothing to score without one. The framework wrappers supply it: give the adapter's actor
wrapper a `getCaller` and whatever it returns becomes the snapshot, the verdict rides along to
`onSession`, and `requestSecurity` refuses a `deny` with `AUTH_ANOMALY_DENIED`. A host calling
`resolveSession` itself calls `anomaly.admit()` once it serves the request.

`getCaller` is also the only way `impossible-travel` is ever fed. The `<name>Caller` helper each adapter
ships reads `ip` and `userAgent`, because those are the two a request carries; a host that resolves
geolocation returns `geo` alongside them and the detector has coordinates to compare:

```ts
getCaller: (req) => ({ ...expressCaller(req), geo: lookup(req.ip) }),
```

`onAnomaly` takes the verdict over from there, and it is the only way to act on a `step-up`: the
default deliberately ignores that one, because it shares its threshold with the device detector's own
score and refusing on it would demand MFA at every first sight of a device.

## What this is not

**Not a gate.** `evaluate` returns a recommendation. A host that never reads `result.decision` is not
protected by having registered a detector, and the score alone refuses nothing.

**Not authoritative about a detector that failed.** A detector that throws, overruns its
`detectorTimeoutMs`, or returns something that is not an array of signals is logged and skipped, and
the aggregate is computed from the rest. That is deliberate — a plugin must not be able to lock every
user out of authn — but it means a detector that is quietly broken reads exactly like one that finds
nothing wrong. Watch the logs, not the verdicts.

**Not a place a detector can see another's work.** They run concurrently, against a frozen request
snapshot, so registration order cannot decide what request any of them scores.

**Not a store of raw request data.** Evidence carries what was derived, never what it was derived
from: the device signal has the fingerprint but not the address or the header, the travel signal the
distance and speed but neither position. The `suspicious` event is persisted wherever the bus is, and
carrying them verbatim would spread them to every sink that reads it.

**Not configured by trust.** Every bound — the three thresholds, `detectorTimeoutMs`, each detector's
own limits, the store's two — is refused at construction when it is not a finite number in range.
Each of them fails open otherwise, and silently: `setTimeout` runs a non-finite delay at 1ms, so a
mistyped timeout abandons every detector before it answers and `evaluate` reports no signals at all.
