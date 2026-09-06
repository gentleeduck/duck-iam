---
'@gentleduck/iam': minor
---

Close the two process-global latches, and give React's `usePermissions` the
`refetch` Vue's has always had.

**React's `usePermissions` could not reach its own stale-map reset.** The effect
deliberately empties `permissions` and clears `error` before each load, for the
sign-out and account-switch cases where the previous subject's grants must not
stay on screen. The only trigger was a change to `deps` — which defaults to `[]`
and was undocumented — so `usePermissions(() => fetchFor(user.id))`, the obvious
call, loaded once and then answered `can()` from the first subject's map
indefinitely. Vue's docblock claimed the two hooks were "the same shape"; they
were not. React's now returns `refetch`, and carries the monotonic run id Vue
uses, which is required once `refetch` exists: two loads can be in flight with no
deps change and therefore no effect teardown between them, and a slow earlier one
would otherwise land on top of a fast later one. A rejection is normalised to an
`Error` rather than declared to be one.

**`IamAccessClient` guarded its map on the way out and not on the way in.** The
`permissions` getter has always returned a copy, because `Readonly<…>` erases at
runtime and an in-place edit would otherwise grant a permission without going
through `update()`/`merge()` — and so without notifying a subscriber. The
constructor and `update()` stored the caller's reference, which is the identical
hazard unguarded. Both copy now; listeners still receive the caller's own object.

**The unsigned-invalidator warning is latched per channel, not per process.**
`tenantId` exists so one process builds one invalidator per tenant, and a single
process-wide boolean meant the second and every later unsigned invalidator
constructed in silence — while the one warning that did fire named no channel, so
an operator who fixed "the" unsigned invalidator had no way to learn the other
forty were still unsigned. The channel is now named in the message, with its
tenant segment redacted the way every other line on that path is.

**The broken-error-hook report is latched per hook, not per process.** One
engine's transiently broken `onPolicyError` permanently silenced a different
engine's — a different tenant's — hook failure for the life of the process, and a
hook failure is how an operator learns that policy evaluation is throwing at all.
`safeErrorReport` now takes the hook and its arguments instead of a
`() => hook?.(…)` thunk, which gives the latch something stable to key on, keeps
the `Error` normalisation in one place instead of six, and stops allocating an
`Error` per throwing policy per request when no hook is wired at all.
