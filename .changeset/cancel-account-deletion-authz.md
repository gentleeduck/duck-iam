---
'@gentleduck/auth': major
---

`cancelAccountDeletion` requires an `authorize` callback.

It checked that `identityId` was a plausible string and then restored the account. No token, no session, no callback. Anyone who could reach the function un-deleted any account by id — including one deleted deliberately, by a user who wanted it gone.

Every sibling in that flow is gated: `completeAccountDeletion` requires a single-use token, `impersonate` refuses to run without an `authorize` callback. This one was gated by nothing, and its own docstring called it an "optional admin cancel route" — an assumption the signature neither stated nor enforced.

```ts
await auth.flows.cancelAccountDeletion({
  identityId,
  authorize: async (id) => currentUser.isAdmin && currentUser.canRestore(id),
})
```

- **Mandatory, not optional.** There is no default the library could pick that is safe; only the host knows who is asking. Required in the type, so every existing call site fails to compile until it says who may cancel.
- **Checked before any read or write.** A refusal never reaches the store, so it cannot be observed as a restore-then-undo or timed against one.
- **A refusal reports `AUTH_UNAUTHENTICATED`** — the same code an unknown identity gets. Distinguishing them would turn the endpoint into a way to ask which accounts are sitting in the deletion grace window.
- **A missing callback is `AUTH_MISCONFIGURED`.** TypeScript refuses the call, but a JavaScript host — or an options object built from parsed input — reaches it anyway, and a missing gate must not read as permission granted.
- The callback receives the **id**, not the identity: the row is soft-deleted at that point and cannot be loaded. Resolve the caller from your own request context.

**Breaking:** `Flows.AccountDeletionCancelInput` gains a required `authorize: (identityId: string) => Promise<boolean>`. Every call site must supply it.

**Not covered:** a cancellation *token*, for a user clicking "undo" in an email without admin rights. Nothing issues one today — `requestAccountDeletion` mints a deletion token that `completeAccountDeletion` consumes — so that path needs a second credential with its own TTL, channel and template. Until it exists, a user-facing undo link is the host's to authorize like any other route.
