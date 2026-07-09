# Core Foldization + Engine Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the provider-owned-config refactor by giving every *core* subject the same encapsulated-folder shape the providers already have — its facet, its types, its constants, its helpers, and its tests all in one folder — then slim `engine.ts` into a thin composition root.

**Architecture:** Today `src/core/` splits each subject across three places: logic in `core/facets/<x>.facet.ts`, types in a shared `core/types/*.ts` bundle, config defaults inline in the facet, tests in `core/facets/__tests__/`. This plan gathers each subject into `src/core/<subject>/` (`<subject>.facet.ts` + `<subject>.types.ts` + `<subject>.constants.ts` + helpers + `__tests__/` + barrel `index.ts`), deletes the shared `core/types/` bundle by relocating every namespace to the folder that owns it (**hard move, no re-export barrels**), homes the three cross-layer namespaces (`Hasher`, `Limiter`, `Channel`) into their real owners (`providers/password`, `limiters`, `channels`), and decomposes `AuthEngine` the way the providers were decomposed.

**Tech Stack:** TypeScript (strict), bun, turbo, vitest, biome, tsdown. `~` path alias → `./src`.

## Global Constraints

- **No type casts.** Never introduce `as X`. Fix types at the source.
- **No deprecation, no shims.** Every retired path/symbol is removed; all call sites updated in the same task. No re-export barrels left behind for moved types. A task's verify grep of retired paths MUST return empty.
- **No `Co-Authored-By` / attribution trailers** in any commit.
- **Conventional commits**, header ≤100 chars.
- **Biome** (not ESLint/Prettier) formats/lints: `bunx biome check --write <paths>`.
- **Verify gate every task:** `bunx tsc --noEmit 2>&1 | grep -c "error TS"` → `0`; full suite `bunx vitest run` → **zero failures, same pass count as the pre-task baseline** (record `N` at Task 0); named retired-symbol/path greps → empty; `bunx biome check --write` on touched dirs.
- **Refactor discipline:** these are behavior-preserving moves. No test's *expectations* change except import specifiers. If a test's assertion would need to change, STOP — that's a behavior change, not a move.
- **Husky pre-commit** runs biome; the pre-existing non-blocking `authAlt`-unused warning predates this work — leave it.

---

## Progress (updated 2026-07-10)

**Group A (Tasks 0–9) — DONE.** Every core facet subject now lives in its own folder: `core/{sessions,identities,provider,orgs,anomaly,hijack,idempotency,operations,m2m}/` each exist with `<x>.facet.ts` + `index.ts` (+ `.constants.ts`/`.types.ts` where applicable). `git grep` for the old `facets/<x>.facet` paths is empty for all nine. Provider-side work also landed out of band (all providers → class+factory, `password`→`passwords` folder, tsdown/exports aligned).

**Remaining `core/facets/` residue:** only `flows.facet.ts` + `flows/*.flow.ts` (6) + `__tests__/flows-*.test.ts` (11) — i.e. **Task 10 is the next actionable step.**

**⚠ Baseline caveat — the tree is currently NOT green.** An out-of-order start on the Group C type-scatter (Tasks 20–23) has removed `Channel` from `~/core/types/infra` and deleted `~/core/types/provider` without repointing importers → **34 `tsc` errors** + ~88 uncommitted files. The plan's per-task gate ("tsc → 0") therefore cannot pass as written. Until Group C is finished (or reverted), Group A/B moves must gate on **"no *new* tsc errors vs the recorded 34-error baseline"** + affected-suite green, not absolute `0`.

---

## Target Layout (end state of `src/core/`)

```
core/
  sessions/       sessions.facet.ts  sessions.types.ts  sessions.constants.ts  index.ts  __tests__/
  identities/     identities.facet.ts  identities.types.ts  identities.constants.ts  index.ts  __tests__/
  provider/       provider.facet.ts  provider.types.ts  provider.helpers.ts  index.ts  __tests__/
  orgs/           orgs.facet.ts  orgs.types.ts  index.ts  __tests__/
  anomaly/        anomaly.facet.ts  anomaly.types.ts  anomaly.constants.ts  *.detector.ts  index.ts  __tests__/
  hijack/         hijack.facet.ts  index.ts  __tests__/
  idempotency/    idempotency.facet.ts  idempotency.types.ts  idempotency.constants.ts  index.ts  __tests__/
  operations/     operations.facet.ts  index.ts  __tests__/
  m2m/            m2m.facet.ts  index.ts  __tests__/
  flows/          flows.facet.ts  flows.constants.ts  *.flow.ts  index.ts  __tests__/
  errors/         errors.ts (AuthError class + namespace + Envelope)  index.ts
  events/         events.ts  events.types.ts  index.ts
  crypto/         crypto.ts  index.ts
  csrf/           csrf.ts  index.ts
  compliance/     compliance.ts  index.ts
  tenant/         tenant.ts  tenant.types.ts  index.ts
  credentials/    credentials.ts  credentials.types.ts  index.ts
  url-validators/ url-validators.ts  index.ts
  plugin/         plugin.ts  index.ts
  transport/      … + transport.types.ts (Transport namespace)
  dataAtRest/     … + dataAtRest.types.ts (Kms + DataAtRest namespaces)
  engine/         engine.ts  engine.types.ts  engine.wiring.ts  engine.strict.ts  engine.resolve-session.ts  index.ts
  captcha/  webhooks/  config/   (already folders — unchanged except import repoints)
```

Cross-layer (outside `core/`):
```
providers/password/  … + password.hasher.types.ts (Hasher namespace)
limiters/            … + limiter.types.ts (Limiter namespace) + NoopLimiter
channels/            … + channel.types.ts (Channel namespace)
```

`src/core/types/` is **deleted** at the end of Group C.

---

## Canonical recipes (each task restates its own exact commands; these describe the shape)

**Recipe F — facet → subject folder.** `git mv` the facet and its co-located tests into `core/<subject>/`; extract inline `DEFAULT_<X>_CONFIG` into `<subject>.constants.ts`; extract the subject's namespace (Group C may do the type half) into `<subject>.types.ts`; add barrel `index.ts`; repoint importers by rewriting the path *segment* `facets/<x>.facet` → `<subject>/<subject>.facet` (works for both `../facets/<x>.facet` and `~/core/facets/<x>.facet` since every facet and every subject folder is a direct child of `core/`). Tests that move *with* the facet keep their `../<x>.facet` relative import unchanged.

**Recipe T — namespace hard-move.** Create `<owner>/<owner>.types.ts` holding the namespace; delete it from the shared `core/types/<file>.ts`; repoint every importer's specifier to the new owner; where one `import { A, B }` line pulled two namespaces that now live in different folders, split it into two import lines. `tsc` enumerates every break; the grep in the verify step must end empty.

---

### Task 0: Baseline

**Files:** none.

- [ ] **Step 1: Record the green baseline.**

Run: `bunx vitest run 2>&1 | tail -3`
Expected: a line like `Tests  <N> passed (<N>)`, zero failed. Record `<N>` — every later task must match it.

- [ ] **Step 2: Confirm clean tsc.**

Run: `bunx tsc --noEmit 2>&1 | grep -c "error TS"`
Expected: `0`

- [ ] **Step 3: Commit any pending trivial churn** (the export-reorder in `core/index.ts` + `providers/mfa/index.ts`, and the staged `core/config/ind.ts` deletion), so the tree is clean before foldization:

```bash
git add -A
git commit -m "chore(duck-auth): tidy barrels before core foldization"
```

---

## Group A — Core facet subjects → folders

### Task 1: `sessions` folder

**Files:**
- Create dir: `src/core/sessions/`
- Move: `src/core/facets/sessions.facet.ts` → `src/core/sessions/sessions.facet.ts`
- Move: `src/core/facets/__tests__/sessions.test.ts` → `src/core/sessions/__tests__/sessions.test.ts`
- Create: `src/core/sessions/sessions.constants.ts`, `src/core/sessions/index.ts`
- Modify: importers of `facets/sessions.facet` (engine + tests)

**Interfaces:**
- Produces: `SessionsFacet`, `DEFAULT_SESSION_CONFIG`, `resolveBySid` from `~/core/sessions`. (`Session` namespace stays in `core/types/session.ts` until Task 21 — this task moves logic only.)

- [ ] **Step 1: Move facet + test into the folder.**
```bash
cd packages/duck-auth
mkdir -p src/core/sessions/__tests__
git mv src/core/facets/sessions.facet.ts src/core/sessions/sessions.facet.ts
git mv src/core/facets/__tests__/sessions.test.ts src/core/sessions/__tests__/sessions.test.ts
```

- [ ] **Step 2: Extract the config default** into `src/core/sessions/sessions.constants.ts`. Cut the `DEFAULT_SESSION_CONFIG` declaration out of `sessions.facet.ts`, paste it here, and add `import { DEFAULT_SESSION_CONFIG } from './sessions.constants'` back into the facet. (If `DEFAULT_SESSION_CONFIG` references only literals, this is a pure cut/paste.)
```ts
// src/core/sessions/sessions.constants.ts
export const DEFAULT_SESSION_CONFIG = /* moved verbatim from sessions.facet.ts */
```

- [ ] **Step 3: Add the barrel.**
```ts
// src/core/sessions/index.ts
export { DEFAULT_SESSION_CONFIG } from './sessions.constants'
export { resolveBySid, SessionsFacet } from './sessions.facet'
```

- [ ] **Step 4: Repoint importers** (rewrite the path segment; the co-moved test already resolves via its own `../sessions.facet`):
```bash
grep -rl --include='*.ts' "facets/sessions.facet" src | xargs sed -i 's#facets/sessions\.facet#sessions/sessions.facet#g'
```

- [ ] **Step 5: Verify.**
```bash
bunx tsc --noEmit 2>&1 | grep -c "error TS"          # 0
grep -rn --include='*.ts' "facets/sessions\.facet" src   # empty
bunx vitest run 2>&1 | tail -3                        # <N> passed, 0 failed
bunx biome check --write src/core/sessions
```

- [ ] **Step 6: Commit.**
```bash
git add -A && git commit -m "refactor(duck-auth): gather sessions facet into core/sessions/"
```

### Task 2: `identities` folder

**Files:**
- Move: `src/core/facets/identities.facet.ts` → `src/core/identities/identities.facet.ts`
- Move: `src/core/facets/__tests__/identities.test.ts` → `src/core/identities/__tests__/identities.test.ts`
- Create: `src/core/identities/identities.constants.ts`, `src/core/identities/index.ts`

**Interfaces:**
- Produces: `IdentitiesFacet`, `DEFAULT_IDENTITIES_CONFIG` from `~/core/identities`.

- [ ] **Step 1: Move.**
```bash
mkdir -p src/core/identities/__tests__
git mv src/core/facets/identities.facet.ts src/core/identities/identities.facet.ts
git mv src/core/facets/__tests__/identities.test.ts src/core/identities/__tests__/identities.test.ts
```
- [ ] **Step 2: Extract `DEFAULT_IDENTITIES_CONFIG`** into `src/core/identities/identities.constants.ts`; import it back into the facet.
- [ ] **Step 3: Barrel.**
```ts
// src/core/identities/index.ts
export { DEFAULT_IDENTITIES_CONFIG } from './identities.constants'
export { IdentitiesFacet } from './identities.facet'
```
- [ ] **Step 4: Repoint.**
```bash
grep -rl --include='*.ts' "facets/identities.facet" src | xargs sed -i 's#facets/identities\.facet#identities/identities.facet#g'
```
- [ ] **Step 5: Verify** — tsc `0`; `grep -rn "facets/identities\.facet" src` empty; suite `<N>` passing; `bunx biome check --write src/core/identities`.
- [ ] **Step 6: Commit** — `refactor(duck-auth): gather identities facet into core/identities/`

### Task 3: `provider` folder (registry)

**Files:**
- Move: `src/core/facets/providers.facet.ts` → `src/core/provider/provider.facet.ts`
- Move: `src/core/facets/__tests__/*provider*`/registry tests if any (there is no dedicated `providers.test.ts`; the flows tests exercise it — leave those in `flows/` at Task 10).
- Create: `src/core/provider/provider.helpers.ts` (holds `isProviderModule`, moved from `engine.ts` in Task 26 — for now just create the folder + facet), `src/core/provider/index.ts`.

**Interfaces:**
- Produces: `ProvidersFacet` from `~/core/provider`. (`Provider` namespace moves here in Task 22.)

- [ ] **Step 1: Move the facet** (rename `providers.facet.ts` → `provider.facet.ts`):
```bash
mkdir -p src/core/provider/__tests__
git mv src/core/facets/providers.facet.ts src/core/provider/provider.facet.ts
```
- [ ] **Step 2: Barrel.**
```ts
// src/core/provider/index.ts
export { ProvidersFacet } from './provider.facet'
```
- [ ] **Step 3: Repoint.**
```bash
grep -rl --include='*.ts' "facets/providers.facet" src | xargs sed -i 's#facets/providers\.facet#provider/provider.facet#g'
```
- [ ] **Step 4: Verify** — tsc `0`; `grep -rn "facets/providers\.facet" src` empty; suite `<N>`; `bunx biome check --write src/core/provider`.
- [ ] **Step 5: Commit** — `refactor(duck-auth): gather provider registry facet into core/provider/`

### Task 4: `orgs` folder

**Files:**
- Move: `src/core/facets/orgs.facet.ts` → `src/core/orgs/orgs.facet.ts`
- Move: `src/core/facets/__tests__/orgs.test.ts`, `orgs-roles-sanitization.test.ts`, `orgs-toctou-add-member.test.ts` → `src/core/orgs/__tests__/`
- Create: `src/core/orgs/index.ts`

**Interfaces:**
- Produces: `OrgsFacet` from `~/core/orgs`. (`Org` namespace moves here in Task 20.)

- [ ] **Step 1: Move.**
```bash
mkdir -p src/core/orgs/__tests__
git mv src/core/facets/orgs.facet.ts src/core/orgs/orgs.facet.ts
git mv src/core/facets/__tests__/orgs.test.ts src/core/orgs/__tests__/orgs.test.ts
git mv src/core/facets/__tests__/orgs-roles-sanitization.test.ts src/core/orgs/__tests__/orgs-roles-sanitization.test.ts
git mv src/core/facets/__tests__/orgs-toctou-add-member.test.ts src/core/orgs/__tests__/orgs-toctou-add-member.test.ts
```
- [ ] **Step 2: Fix the moved tests' facet import** if they referenced `../orgs.facet` they still resolve; if they referenced `../../facets/orgs.facet` rewrite to `../orgs.facet`:
```bash
sed -i 's#\.\./\.\./facets/orgs\.facet#../orgs.facet#g; s#\.\./orgs\.facet#../orgs.facet#g' src/core/orgs/__tests__/*.ts
```
- [ ] **Step 3: Barrel.**
```ts
// src/core/orgs/index.ts
export { OrgsFacet } from './orgs.facet'
```
- [ ] **Step 4: Repoint non-test importers.**
```bash
grep -rl --include='*.ts' "facets/orgs.facet" src | xargs sed -i 's#facets/orgs\.facet#orgs/orgs.facet#g'
```
- [ ] **Step 5: Verify** — tsc `0`; `grep -rn "facets/orgs\.facet" src` empty; suite `<N>`; `bunx biome check --write src/core/orgs`.
- [ ] **Step 6: Commit** — `refactor(duck-auth): gather orgs facet into core/orgs/`

### Task 5: `anomaly` folder (facet joins the detectors already here)

**Files:**
- Move: `src/core/facets/anomaly.facet.ts` → `src/core/anomaly/anomaly.facet.ts`
- Move: `src/core/facets/__tests__/anomaly.test.ts` → `src/core/anomaly/__tests__/anomaly.test.ts`
- Existing: `src/core/anomaly/device-fingerprint.detector.ts`, `impossible-travel.detector.ts`
- Create: `src/core/anomaly/anomaly.constants.ts` (`DEFAULT_ANOMALY_CONFIG`), `src/core/anomaly/index.ts`

**Interfaces:**
- Produces: `AnomalyFacet`, `DEFAULT_ANOMALY_CONFIG`, the two detectors from `~/core/anomaly`. (`Anomaly` namespace moves here in Task 22.)

- [ ] **Step 1: Move facet + test** into the existing `anomaly/` dir.
```bash
mkdir -p src/core/anomaly/__tests__
git mv src/core/facets/anomaly.facet.ts src/core/anomaly/anomaly.facet.ts
git mv src/core/facets/__tests__/anomaly.test.ts src/core/anomaly/__tests__/anomaly.test.ts
```
- [ ] **Step 2: Extract `DEFAULT_ANOMALY_CONFIG`** into `anomaly.constants.ts`; import it back into the facet. Fix the facet's detector imports (they were `../anomaly/*.detector`; now co-located → `./device-fingerprint.detector`, `./impossible-travel.detector`):
```bash
sed -i 's#\.\./anomaly/\([a-z-]*\.detector\)#./\1#g' src/core/anomaly/anomaly.facet.ts
```
- [ ] **Step 3: Barrel.**
```ts
// src/core/anomaly/index.ts
export { AnomalyFacet } from './anomaly.facet'
export { DEFAULT_ANOMALY_CONFIG } from './anomaly.constants'
export { DeviceFingerprintDetector } from './device-fingerprint.detector'   // use the real export names
export { ImpossibleTravelDetector } from './impossible-travel.detector'
```
- [ ] **Step 4: Repoint importers** of the facet:
```bash
grep -rl --include='*.ts' "facets/anomaly.facet" src | xargs sed -i 's#facets/anomaly\.facet#anomaly/anomaly.facet#g'
```
- [ ] **Step 5: Verify** — tsc `0`; `grep -rn "facets/anomaly\.facet" src` empty; suite `<N>`; `bunx biome check --write src/core/anomaly`.
- [ ] **Step 6: Commit** — `refactor(duck-auth): unite anomaly facet with its detectors in core/anomaly/`

### Task 6: `hijack` folder

**Files:**
- Move: `src/core/facets/hijack.facet.ts` → `src/core/hijack/hijack.facet.ts`
- Move: `src/core/facets/__tests__/hijack.test.ts`, `hijack-diagnostic-clip.test.ts` → `src/core/hijack/__tests__/`
- Create: `src/core/hijack/index.ts`

- [ ] **Step 1: Move.**
```bash
mkdir -p src/core/hijack/__tests__
git mv src/core/facets/hijack.facet.ts src/core/hijack/hijack.facet.ts
git mv src/core/facets/__tests__/hijack.test.ts src/core/hijack/__tests__/hijack.test.ts
git mv src/core/facets/__tests__/hijack-diagnostic-clip.test.ts src/core/hijack/__tests__/hijack-diagnostic-clip.test.ts
```
- [ ] **Step 2: Fix moved-test imports** to `../hijack.facet`:
```bash
sed -i 's#\.\./\.\./facets/hijack\.facet#../hijack.facet#g' src/core/hijack/__tests__/*.ts
```
- [ ] **Step 3: Barrel.**
```ts
// src/core/hijack/index.ts
export { HijackFacet } from './hijack.facet'
```
- [ ] **Step 4: Repoint.**
```bash
grep -rl --include='*.ts' "facets/hijack.facet" src | xargs sed -i 's#facets/hijack\.facet#hijack/hijack.facet#g'
```
- [ ] **Step 5: Verify** — tsc `0`; `grep -rn "facets/hijack\.facet" src` empty; suite `<N>`; biome write `src/core/hijack`.
- [ ] **Step 6: Commit** — `refactor(duck-auth): gather hijack facet into core/hijack/`

### Task 7: `idempotency` folder

**Files:**
- Move: `src/core/facets/idempotency.facet.ts` → `src/core/idempotency/idempotency.facet.ts`
- Move: `src/core/facets/__tests__/idempotency.test.ts` → `src/core/idempotency/__tests__/idempotency.test.ts`
- Create: `src/core/idempotency/idempotency.constants.ts` (`DEFAULT_IDEMPOTENCY_CONFIG`), `src/core/idempotency/index.ts`

**Interfaces:**
- Produces: `IdempotencyFacet`, `MemoryIdempotencyStore`, `DEFAULT_IDEMPOTENCY_CONFIG` from `~/core/idempotency`. (`Idempotency` namespace moves here in Task 23.)

- [ ] **Step 1: Move.** (the test imports `../idempotency.facet`, unchanged after co-move)
```bash
mkdir -p src/core/idempotency/__tests__
git mv src/core/facets/idempotency.facet.ts src/core/idempotency/idempotency.facet.ts
git mv src/core/facets/__tests__/idempotency.test.ts src/core/idempotency/__tests__/idempotency.test.ts
```
- [ ] **Step 2: Extract `DEFAULT_IDEMPOTENCY_CONFIG`** into `idempotency.constants.ts`; import it back into the facet.
- [ ] **Step 3: Barrel.**
```ts
// src/core/idempotency/index.ts
export { DEFAULT_IDEMPOTENCY_CONFIG } from './idempotency.constants'
export { IdempotencyFacet, MemoryIdempotencyStore } from './idempotency.facet'
```
- [ ] **Step 4: Repoint.**
```bash
grep -rl --include='*.ts' "facets/idempotency.facet" src | xargs sed -i 's#facets/idempotency\.facet#idempotency/idempotency.facet#g'
```
- [ ] **Step 5: Verify** — tsc `0`; `grep -rn "facets/idempotency\.facet" src` empty; suite `<N>`; biome write `src/core/idempotency`.
- [ ] **Step 6: Commit** — `refactor(duck-auth): gather idempotency facet into core/idempotency/`

### Task 8: `operations` folder

**Files:**
- Move: `src/core/facets/operations.facet.ts` → `src/core/operations/operations.facet.ts`
- Move: `src/core/facets/__tests__/operations.test.ts` → `src/core/operations/__tests__/operations.test.ts`
- Create: `src/core/operations/index.ts`

- [ ] **Step 1: Move.**
```bash
mkdir -p src/core/operations/__tests__
git mv src/core/facets/operations.facet.ts src/core/operations/operations.facet.ts
git mv src/core/facets/__tests__/operations.test.ts src/core/operations/__tests__/operations.test.ts
```
- [ ] **Step 2: Barrel.**
```ts
// src/core/operations/index.ts
export { OperationsFacet } from './operations.facet'
```
- [ ] **Step 3: Repoint.**
```bash
grep -rl --include='*.ts' "facets/operations.facet" src | xargs sed -i 's#facets/operations\.facet#operations/operations.facet#g'
```
- [ ] **Step 4: Verify** — tsc `0`; `grep -rn "facets/operations\.facet" src` empty; suite `<N>`; biome write `src/core/operations`.
- [ ] **Step 5: Commit** — `refactor(duck-auth): gather operations facet into core/operations/`

### Task 9: `m2m` folder

**Files:**
- Move: `src/core/facets/m2m.facet.ts` → `src/core/m2m/m2m.facet.ts`
- Move: `src/core/facets/__tests__/m2m.test.ts` → `src/core/m2m/__tests__/m2m.test.ts`
- Create: `src/core/m2m/index.ts`

Note: `m2m.facet.ts` imports the api-key facet (`~/providers/api-key/api-key.facet`) — that import is absolute, unaffected by the move. The `m2m.test.ts` builds an engine and (per earlier work) registers `apiKeyProvider()`; leave that as-is.

- [ ] **Step 1: Move.**
```bash
mkdir -p src/core/m2m/__tests__
git mv src/core/facets/m2m.facet.ts src/core/m2m/m2m.facet.ts
git mv src/core/facets/__tests__/m2m.test.ts src/core/m2m/__tests__/m2m.test.ts
```
- [ ] **Step 2: Fix moved-test import** to `../m2m.facet` if it used `../../facets/m2m.facet`:
```bash
sed -i 's#\.\./\.\./facets/m2m\.facet#../m2m.facet#g' src/core/m2m/__tests__/m2m.test.ts
```
- [ ] **Step 3: Barrel.**
```ts
// src/core/m2m/index.ts
export { M2mFacet } from './m2m.facet'   // use the real exported class name
```
- [ ] **Step 4: Repoint.**
```bash
grep -rl --include='*.ts' "facets/m2m.facet" src | xargs sed -i 's#facets/m2m\.facet#m2m/m2m.facet#g'
```
- [ ] **Step 5: Verify** — tsc `0`; `grep -rn "facets/m2m\.facet" src` empty; suite `<N>`; biome write `src/core/m2m`.
- [ ] **Step 6: Commit** — `refactor(duck-auth): gather m2m facet into core/m2m/`

### Task 10: `flows` folder (facet joins its `*.flow.ts` steps)

**Files:**
- Move: `src/core/facets/flows.facet.ts` → `src/core/flows/flows.facet.ts`
- Move: `src/core/facets/flows/*.flow.ts` → `src/core/flows/*.flow.ts` (six files)
- Move: all `src/core/facets/__tests__/flows-*.test.ts` (11 files) → `src/core/flows/__tests__/`
- Create: `src/core/flows/flows.constants.ts` (`DEFAULT_FLOWS_CONFIG`), `src/core/flows/index.ts`

**Interfaces:**
- Produces: `FlowsFacet`, `DEFAULT_FLOWS_CONFIG` from `~/core/flows`.

- [ ] **Step 1: Move facet, flow-steps, and tests.**
```bash
mkdir -p src/core/flows/__tests__
git mv src/core/facets/flows.facet.ts src/core/flows/flows.facet.ts
git mv src/core/facets/flows/account-deletion.flow.ts src/core/flows/account-deletion.flow.ts
git mv src/core/facets/flows/email-verification.flow.ts src/core/flows/email-verification.flow.ts
git mv src/core/facets/flows/impersonate.flow.ts src/core/flows/impersonate.flow.ts
git mv src/core/facets/flows/password-reset.flow.ts src/core/flows/password-reset.flow.ts
git mv src/core/facets/flows/provider-link.flow.ts src/core/flows/provider-link.flow.ts
git mv src/core/facets/flows/signup.flow.ts src/core/flows/signup.flow.ts
git mv src/core/facets/__tests__/flows-account-deletion.test.ts src/core/flows/__tests__/
git mv src/core/facets/__tests__/flows-callback-path-sanitization.test.ts src/core/flows/__tests__/
git mv src/core/facets/__tests__/flows-email-verification.test.ts src/core/flows/__tests__/
git mv src/core/facets/__tests__/flows-extracts-direct.test.ts src/core/flows/__tests__/
git mv src/core/facets/__tests__/flows-linking.test.ts src/core/flows/__tests__/
git mv src/core/facets/__tests__/flows-link-toctou.test.ts src/core/flows/__tests__/
git mv src/core/facets/__tests__/flows-password-reset-timing-defense.test.ts src/core/flows/__tests__/
git mv src/core/facets/__tests__/flows-provider-id-cap.test.ts src/core/flows/__tests__/
git mv src/core/facets/__tests__/flows-signup-impersonate.test.ts src/core/flows/__tests__/
git mv src/core/facets/__tests__/flows-signup-tampered-flow.test.ts src/core/flows/__tests__/
git mv src/core/facets/__tests__/flows-stepup-recovery.test.ts src/core/flows/__tests__/
```
- [ ] **Step 2: Fix intra-flows imports.** `flows.facet.ts` imported its steps as `./flows/<x>.flow`; now co-located → `./<x>.flow`:
```bash
sed -i 's#\./flows/\([a-z-]*\.flow\)#./\1#g' src/core/flows/flows.facet.ts
```
The moved tests referenced either `../flows.facet` (unchanged) or `../../facets/flows/<x>.flow`; normalize:
```bash
sed -i 's#\.\./\.\./facets/flows\.facet#../flows.facet#g; s#\.\./\.\./facets/flows/\([a-z-]*\.flow\)#../\1#g; s#\.\./flows/\([a-z-]*\.flow\)#../\1#g' src/core/flows/__tests__/*.ts
```
- [ ] **Step 3: Extract `DEFAULT_FLOWS_CONFIG`** into `flows.constants.ts`; import it back into the facet.
- [ ] **Step 4: Barrel.**
```ts
// src/core/flows/index.ts
export { DEFAULT_FLOWS_CONFIG } from './flows.constants'
export { FlowsFacet } from './flows.facet'
```
- [ ] **Step 5: Repoint external importers** of the facet:
```bash
grep -rl --include='*.ts' "facets/flows.facet" src | xargs sed -i 's#facets/flows\.facet#flows/flows.facet#g'
```
- [ ] **Step 6: Remove the now-empty `facets/` dir** (it should contain only `__tests__/` husk):
```bash
rmdir src/core/facets/flows 2>/dev/null; rmdir src/core/facets/__tests__ 2>/dev/null; rmdir src/core/facets 2>/dev/null
```
Expected: all three `rmdir` succeed (empty). If any fails, `ls` it — a stray file was missed above; move it, don't force.
- [ ] **Step 7: Verify** — tsc `0`; `grep -rn "core/facets" src` empty; suite `<N>`; biome write `src/core/flows`.
- [ ] **Step 8: Commit** — `refactor(duck-auth): unite flows facet with its steps in core/flows/; retire core/facets/`

---

## Group B — Loose primitives → folders

Each: `git mv <file>.ts <name>/<name>.ts`; add barrel; repoint the path segment `core/<name>'` (bare-file import) → `core/<name>/index` resolves automatically since the folder's `index.ts` is the new module — but bare `~/core/<name>` currently resolves to the FILE; after the move it resolves to the FOLDER's `index.ts`. So importers using `~/core/<name>` need **no change**; only importers using a deeper `~/core/<name>/…` (none exist for these flat files) would. Verify with grep.

### Task 11: `errors` folder (class + namespace + Envelope, merged)

**Files:**
- Move: `src/core/errors.ts` → `src/core/errors/errors.ts`
- Create: `src/core/errors/index.ts`
- Modify (in Task 21 this folder also absorbs the `AuthError` namespace + `Envelope` from `types/session.ts`; do the file move now, the type absorption in Task 21).

- [ ] **Step 1: Move.**
```bash
mkdir -p src/core/errors
git mv src/core/errors.ts src/core/errors/errors.ts
```
- [ ] **Step 2: Barrel.**
```ts
// src/core/errors/index.ts
export { AuthError } from './errors'   // add error-code exports if errors.ts exports any
```
- [ ] **Step 3: Repoint deep importers** (those importing `~/core/errors` now hit the folder barrel automatically; fix any that used a file-only relative like `../errors` from within `core/`):
```bash
grep -rl --include='*.ts' "core/errors'" src | head   # sanity: these resolve to the folder now
grep -rl --include='*.ts' "from '\.\./errors'" src/core | xargs -r sed -i "s#from '\.\./errors'#from '../errors/errors'#g"
grep -rl --include='*.ts' "from '\./errors'" src/core | xargs -r sed -i "s#from '\./errors'#from './errors/errors'#g"
```
- [ ] **Step 4: Verify** — tsc `0`; suite `<N>`; biome write `src/core/errors`.
- [ ] **Step 5: Commit** — `refactor(duck-auth): move errors into core/errors/`

### Task 12: `events` folder

**Files:**
- Move: `src/core/events.ts` → `src/core/events/events.ts`
- Create: `src/core/events/index.ts` (Task 22 adds `events.types.ts` with the `Events` namespace)

- [ ] **Step 1: Move + barrel + repoint** (same shape as Task 11 with `events`):
```bash
mkdir -p src/core/events
git mv src/core/events.ts src/core/events/events.ts
printf "export { InMemoryEvents } from './events'\n" > src/core/events/index.ts
grep -rl --include='*.ts' "from '\.\./events'" src/core | xargs -r sed -i "s#from '\.\./events'#from '../events/events'#g"
grep -rl --include='*.ts' "from '\./events'" src/core | xargs -r sed -i "s#from '\./events'#from './events/events'#g"
```
- [ ] **Step 2: Verify** — tsc `0`; suite `<N>`; biome write `src/core/events`.
- [ ] **Step 3: Commit** — `refactor(duck-auth): move events into core/events/`

### Task 13–19: `crypto`, `csrf`, `compliance`, `tenant`, `credentials`, `url-validators`, `plugin`

Identical shape to Task 11/12. For each `<name>` (source file → folder):

| Task | Source file | Folder | Barrel export (use real symbol names) |
|------|-------------|--------|----------------------------------------|
| 13 | `crypto.ts` | `crypto/` | `randomToken, sha256, timingSafeEqual, …` |
| 14 | `csrf.ts` | `csrf/` | csrf helpers |
| 15 | `compliance.ts` | `compliance/` | `resolveCompliance, applyCompliancePreset, …` |
| 16 | `tenant.ts` | `tenant/` | `currentTenant, resolveTenant, …` (Task 23 adds `tenant.types.ts` = `TenantContext`) |
| 17 | `credential-utils.ts` | `credentials/` (file → `credentials.ts`) | credential helpers (Task 20 adds `credentials.types.ts` = `Credential`) |
| 18 | `url-validators.ts` | `url-validators/` | url validators |
| 19 | `plugin.ts` | `plugin/` | `PluginRegistry` |

- [ ] **Step 1 (each):** `mkdir -p src/core/<folder>` then `git mv src/core/<source> src/core/<folder>/<basename>`. For Task 17 rename: `git mv src/core/credential-utils.ts src/core/credentials/credentials.ts`.
- [ ] **Step 2 (each):** write `src/core/<folder>/index.ts` re-exporting the real symbols from the moved file (open the file, copy its `export` names).
- [ ] **Step 3 (each):** repoint intra-`core` relative importers:
```bash
# example for crypto — substitute <name>=crypto|csrf|compliance|tenant|url-validators|plugin and <base>=the moved file basename
grep -rl --include='*.ts' "from '\.\./<name>'" src/core | xargs -r sed -i "s#from '\.\./<name>'#from '../<name>/<base>'#g"
grep -rl --include='*.ts' "from '\./<name>'" src/core | xargs -r sed -i "s#from '\./<name>'#from './<name>/<base>'#g"
```
For Task 17 the specifier also changes name: `credential-utils` → `credentials/credentials`:
```bash
grep -rl --include='*.ts' "credential-utils" src | xargs -r sed -i 's#core/credential-utils#core/credentials/credentials#g; s#\.\./credential-utils#../credentials/credentials#g; s#\./credential-utils#./credentials/credentials#g'
```
- [ ] **Step 4 (each):** Verify — tsc `0`; `grep -rn "core/<source-basename-without-folder>'" src` returns only folder-resolved hits (no dangling); suite `<N>`; biome write `src/core/<folder>`.
- [ ] **Step 5 (each):** Commit — `refactor(duck-auth): move <name> into core/<folder>/`

---

## Group C — Namespace hard-moves (delete `core/types/`)

Do these **after** Group A/B so every destination folder exists. Each task follows **Recipe T**. The shared file `core/types/index.ts` re-exports everything today; it is deleted in Task 24. `core/types/*.ts` deep imports number ~131 — expect wide repoints. Work one shared file at a time; keep tsc green between namespaces where practical.

### Task 20: `Identity`, `Credential`, `Org` out of `types/identity.ts`

**Files:**
- Create: `src/core/identities/identities.types.ts` (`Identity` namespace)
- Create: `src/core/credentials/credentials.types.ts` (`Credential` namespace + `AUTH_CREDENTIAL_KINDS`)
- Create: `src/core/orgs/orgs.types.ts` (`Org` namespace)
- Delete: `src/core/types/identity.ts`

**Interfaces:**
- Produces: `Identity` from `~/core/identities`, `Credential` + `AUTH_CREDENTIAL_KINDS` from `~/core/credentials`, `Org` from `~/core/orgs`.

- [ ] **Step 1: Split the file.** Copy the `Identity` namespace (lines around 8–66) into `identities.types.ts`; `AUTH_CREDENTIAL_KINDS` + `Credential` namespace into `credentials.types.ts`; `Org` namespace into `orgs.types.ts`. `Identity` is referenced by `Credential`/`Org`? Check: if `Org.Membership`/`Credential.Me` reference `Identity`, add `import { Identity } from '~/core/identities/identities.types'` to those files.
- [ ] **Step 2: Extend the barrels.**
```ts
// append to src/core/identities/index.ts
export type { Identity } from './identities.types'
// append to src/core/credentials/index.ts
export { AUTH_CREDENTIAL_KINDS } from './credentials.types'
export type { Credential } from './credentials.types'
// append to src/core/orgs/index.ts
export type { Org } from './orgs.types'
```
- [ ] **Step 3: Delete the shared file and repoint.**
```bash
git rm src/core/types/identity.ts
# repoint deep imports; split multi-namespace lines by hand where flagged
grep -rl --include='*.ts' "core/types/identity'" src | xargs -r sed -i \
  -e "s#import type { Identity } from '\(~/core\|\.\.*\)/types/identity'#import type { Identity } from '~/core/identities/identities.types'#g" \
  -e "s#import type { Credential } from '\(~/core\|\.\.*\)/types/identity'#import type { Credential } from '~/core/credentials/credentials.types'#g" \
  -e "s#import type { Org } from '\(~/core\|\.\.*\)/types/identity'#import type { Org } from '~/core/orgs/orgs.types'#g"
```
- [ ] **Step 4: Hand-split remaining multi-namespace imports.** List them and edit each so each namespace imports from its owner:
```bash
grep -rn --include='*.ts' "types/identity'" src   # any survivor pulls 2+ of {Identity,Credential,Org} on one line — split it
```
- [ ] **Step 5: Verify** — tsc `0`; `grep -rn "types/identity'" src` empty; suite `<N>`; biome write on touched dirs.
- [ ] **Step 6: Commit** — `refactor(duck-auth): home Identity/Credential/Org types in their subject folders`

### Task 21: `Session`, `Transport`, `AuthError`, `Envelope` out of `types/session.ts`

**Files:**
- Create: `src/core/sessions/sessions.types.ts` (`Session` namespace + `AUTH_SESSION_KINDS` + `AUTH_SESSION_FACTOR_METHODS`)
- Create: `src/core/transport/transport.types.ts` (`Transport` namespace)
- Append to `src/core/errors/errors.ts`: the `AuthError` namespace (declaration-merges with the existing `AuthError` class in the same file) + the `Envelope<T,C>` type
- Delete: `src/core/types/session.ts`

**Interfaces:**
- Produces: `Session` + the two const arrays from `~/core/sessions`; `Transport` from `~/core/transport`; `AuthError` (class+namespace) + `Envelope` from `~/core/errors`.

- [ ] **Step 1: Split.** Move `Session` (+ the two `AUTH_SESSION_*` consts) → `sessions.types.ts`; `Transport` → `transport.types.ts`; paste the `AuthError` namespace body **into `errors/errors.ts` directly below the class** so `class AuthError` + `namespace AuthError` merge; paste `Envelope` after it. `Transport.CookieOptions` is referenced by `Provider.CookieOptions` (Task 22) — that import resolves once `transport.types.ts` exists.
- [ ] **Step 2: Extend barrels.**
```ts
// append to src/core/sessions/index.ts
export { AUTH_SESSION_FACTOR_METHODS, AUTH_SESSION_KINDS } from './sessions.types'
export type { Session } from './sessions.types'
// create/extend src/core/transport/index.ts (it exists) — add:
export type { Transport } from './transport.types'
// append to src/core/errors/index.ts
export type { Envelope } from './errors'
```
- [ ] **Step 3: Delete + repoint** (specifier per namespace):
```bash
git rm src/core/types/session.ts
grep -rl --include='*.ts' "types/session'" src | xargs -r sed -i \
  -e "s#{ Session } from '\(~/core\|\.\.*\)/types/session'#{ Session } from '~/core/sessions/sessions.types'#g" \
  -e "s#{ Transport } from '\(~/core\|\.\.*\)/types/session'#{ Transport } from '~/core/transport/transport.types'#g" \
  -e "s#{ AuthError } from '\(~/core\|\.\.*\)/types/session'#{ AuthError } from '~/core/errors/errors'#g" \
  -e "s#{ Envelope } from '\(~/core\|\.\.*\)/types/session'#{ Envelope } from '~/core/errors/errors'#g"
```
- [ ] **Step 4: Hand-split** any multi-namespace survivors:
```bash
grep -rn --include='*.ts' "types/session'" src   # split each remaining line per owner
```
- [ ] **Step 5: Verify** — tsc `0`; `grep -rn "types/session'" src` empty; suite `<N>`; biome write touched dirs.
- [ ] **Step 6: Commit** — `refactor(duck-auth): home Session/Transport/AuthError types in their owners`

### Task 22: `Provider`, `Events`, `Anomaly` out of `types/provider.ts`

**Files:**
- Create: `src/core/provider/provider.types.ts` (`Provider` namespace)
- Create: `src/core/events/events.types.ts` (`Events` namespace)
- Create: `src/core/anomaly/anomaly.types.ts` (`Anomaly` namespace)
- Delete: `src/core/types/provider.ts`

**Interfaces:**
- Produces: `Provider` from `~/core/provider`; `Events` from `~/core/events`; `Anomaly` from `~/core/anomaly`.

- [ ] **Step 1: Split.** `Provider` → `provider.types.ts` (it imports `Transport`, `Identity` — repoint those to `~/core/transport/transport.types`, `~/core/identities/identities.types`); `Events` → `events.types.ts`; `Anomaly` → `anomaly.types.ts`.
- [ ] **Step 2: Extend barrels.**
```ts
// append to src/core/provider/index.ts
export type { Provider } from './provider.types'
// append to src/core/events/index.ts
export type { Events } from './events.types'
// append to src/core/anomaly/index.ts
export type { Anomaly } from './anomaly.types'
```
- [ ] **Step 3: Delete + repoint.**
```bash
git rm src/core/types/provider.ts
grep -rl --include='*.ts' "types/provider'" src | xargs -r sed -i \
  -e "s#{ Provider } from '\(~/core\|\.\.*\)/types/provider'#{ Provider } from '~/core/provider/provider.types'#g" \
  -e "s#{ Events } from '\(~/core\|\.\.*\)/types/provider'#{ Events } from '~/core/events/events.types'#g" \
  -e "s#{ Anomaly } from '\(~/core\|\.\.*\)/types/provider'#{ Anomaly } from '~/core/anomaly/anomaly.types'#g"
```
- [ ] **Step 4: Hand-split** survivors: `grep -rn --include='*.ts' "types/provider'" src`.
- [ ] **Step 5: Verify** — tsc `0`; `grep -rn "types/provider'" src` empty; suite `<N>`; biome write touched dirs.
- [ ] **Step 6: Commit** — `refactor(duck-auth): home Provider/Events/Anomaly types in their owners`

### Task 23: `types/infra.ts` scatter → 6 owners + delete `types/`

**Files:**
- Create: `src/core/idempotency/idempotency.types.ts` (`Idempotency`), `src/core/dataAtRest/dataAtRest.types.ts` (`Kms` + `DataAtRest`), `src/core/tenant/tenant.types.ts` (`TenantContext`)
- Create: `src/providers/password/password.hasher.types.ts` (`Hasher`), `src/limiters/limiter.types.ts` (`Limiter`), `src/channels/channel.types.ts` (`Channel`)
- Delete: `src/core/types/infra.ts` and `src/core/types/index.ts` (and `rmdir src/core/types`)

**Interfaces:**
- Produces: `Idempotency` from `~/core/idempotency`; `Kms`,`DataAtRest` from `~/core/dataAtRest`; `TenantContext` from `~/core/tenant`; `Hasher` from `~/providers/password`; `Limiter` from `~/limiters`; `Channel` from `~/channels`.

- [ ] **Step 1: Split infra.ts** into the six destination files listed above (namespace-per-owner). Extend each destination barrel (`idempotency/index.ts`, `dataAtRest/index.ts`, `tenant/index.ts`, `providers/password/index.ts`, `limiters/index.ts` (create if absent), `channels/index.ts` (create if absent)) with `export type { … }`.
- [ ] **Step 2: Delete shared files.**
```bash
git rm src/core/types/infra.ts src/core/types/index.ts
```
- [ ] **Step 3: Repoint infra importers per namespace.**
```bash
grep -rl --include='*.ts' "types/infra'" src | xargs -r sed -i \
  -e "s#{ Idempotency } from '\(~/core\|\.\.*\)/types/infra'#{ Idempotency } from '~/core/idempotency/idempotency.types'#g" \
  -e "s#{ Kms } from '\(~/core\|\.\.*\)/types/infra'#{ Kms } from '~/core/dataAtRest/dataAtRest.types'#g" \
  -e "s#{ DataAtRest } from '\(~/core\|\.\.*\)/types/infra'#{ DataAtRest } from '~/core/dataAtRest/dataAtRest.types'#g" \
  -e "s#{ TenantContext } from '\(~/core\|\.\.*\)/types/infra'#{ TenantContext } from '~/core/tenant/tenant.types'#g" \
  -e "s#{ Hasher } from '\(~/core\|\.\.*\)/types/infra'#{ Hasher } from '~/providers/password/password.hasher.types'#g" \
  -e "s#{ Limiter } from '\(~/core\|\.\.*\)/types/infra'#{ Limiter } from '~/limiters/limiter.types'#g" \
  -e "s#{ Channel } from '\(~/core\|\.\.*\)/types/infra'#{ Channel } from '~/channels/channel.types'#g"
```
- [ ] **Step 4: Repoint any `~/core/types` barrel imports** (the ~13 barrel users) to the specific owners, then remove the dir:
```bash
grep -rn --include='*.ts' "from '~/core/types'" src   # rewrite each to its owner folder (per namespace)
grep -rn --include='*.ts' "from '\.\./types'" src      # same
rmdir src/core/types 2>/dev/null && echo "types/ removed" || { echo "types/ not empty:"; ls src/core/types; }
```
- [ ] **Step 5: Hand-split** survivors: `grep -rn --include='*.ts' "core/types" src` → must be empty.
- [ ] **Step 6: Verify** — tsc `0`; `grep -rn "core/types" src` empty; suite `<N>`; biome write on all touched dirs.
- [ ] **Step 7: Commit** — `refactor(duck-auth): scatter types/infra to owners and delete core/types/`

### Task 24: Update `scripts/audit-namespaces.ts` OWNER_OVERRIDES

**Files:** Modify `scripts/audit-namespaces.ts`.

- [ ] **Step 1:** Update the `OWNER_OVERRIDES` map so each relocated namespace (`Session`,`Transport`,`AuthError`,`Envelope`,`Provider`,`Events`,`Anomaly`,`Identity`,`Credential`,`Org`,`Idempotency`,`Kms`,`DataAtRest`,`TenantContext`,`Hasher`,`Limiter`,`Channel`) points at its new file.
- [ ] **Step 2: Run the audit.**
Run: `bunx tsx scripts/audit-namespaces.ts` (or the repo's documented invocation)
Expected: exits `0`, no "owner mismatch".
- [ ] **Step 3: Commit** — `chore(duck-auth): point namespace audit at relocated type owners`

---

## Group D — Engine cleanup (decompose `AuthEngine` like the providers)

`engine.ts` is 330 lines carrying: the `AuthEngine` class (facet slots + provider getters/setters + constructor wiring + `resolveSession` + `use` + `strict`), the free helper `isProviderModule`, a `SessionsFacet` re-export, `__hashSid`, and `NoopLimiter`. Split the non-class pieces out and reduce the constructor/`strict`/`resolveSession` bodies to delegations.

### Task 25: Move `NoopLimiter` to `limiters/`

**Files:**
- Create: `src/limiters/noop.ts` (`NoopLimiter`)
- Modify: `src/core/engine/engine.ts` (remove `NoopLimiter`, lines ~320–329), `src/limiters/index.ts` (export it)

- [ ] **Step 1: Cut `NoopLimiter`** (class + `__isNoopLimiter` marker) from `engine.ts` into `src/limiters/noop.ts`; it implements `Limiter.Limiter` → `import type { Limiter } from './limiter.types'`.
- [ ] **Step 2: Re-export** from `src/limiters/index.ts`: `export { NoopLimiter } from './noop'`.
- [ ] **Step 3: Repoint importers** of `NoopLimiter` (grep) to `~/limiters`.
```bash
grep -rl --include='*.ts' "NoopLimiter" src | xargs -r sed -i "s#from '.*engine/engine'#from '~/limiters'#g"   # only where the sole import was NoopLimiter; else hand-edit
```
- [ ] **Step 4: Verify** — tsc `0`; suite `<N>`; `grep -rn "NoopLimiter" src/core/engine/engine.ts` empty; biome write.
- [ ] **Step 5: Commit** — `refactor(duck-auth): move NoopLimiter into limiters/`

### Task 26: Move `isProviderModule` into `core/provider/`

**Files:**
- Modify: `src/core/provider/provider.helpers.ts` (add `isProviderModule`), `src/core/engine/engine.ts` (remove it, import from `~/core/provider`)

- [ ] **Step 1: Cut `isProviderModule`** (the free function, ~lines 303–309) from `engine.ts` into `src/core/provider/provider.helpers.ts`; export it; re-export from `provider/index.ts`.
- [ ] **Step 2: Import it** in `engine.ts`: `import { isProviderModule } from '~/core/provider'`.
- [ ] **Step 3: Verify** — tsc `0`; suite `<N>`; biome write.
- [ ] **Step 4: Commit** — `refactor(duck-auth): move isProviderModule into core/provider/`

### Task 27: Extract `strict()` body → `engine.strict.ts`

**Files:**
- Create: `src/core/engine/engine.strict.ts` — `export function assertStrict<…>(engine: AuthEngine<…>, opts: { env: 'development'|'production'|'test' }): void`
- Modify: `engine.ts` — `strict(opts) { assertStrict(this, opts) }`

- [ ] **Step 1: Move the body.** Copy the current `strict()` body (~lines 235–302) into `assertStrict(engine, opts)`, replacing `this.` with `engine.`. Keep every validation and every thrown `AuthError` identical.
- [ ] **Step 2: Delegate.** In `engine.ts`: `strict(opts: { env: 'development' | 'production' | 'test' }): void { assertStrict(this, opts) }` and `import { assertStrict } from './engine.strict'`.
- [ ] **Step 3: Verify** — tsc `0`; the strict-mode tests in `core/__tests__/define-auth.test.ts` (`strict("production")…`, `strict("development")…`) still pass; suite `<N>`; biome write.
- [ ] **Step 4: Commit** — `refactor(duck-auth): extract engine.strict assertStrict`

### Task 28: Extract `resolveSession()` body → `engine.resolve-session.ts`

**Files:**
- Create: `src/core/engine/engine.resolve-session.ts` — `export async function resolveSession<…>(engine: AuthEngine<…>, token: string, opts?: { expectedTenantId?: string; requestSnapshot?: Anomaly.RequestSnapshot }): Promise<…>` (return type copied verbatim from the current method signature, ~lines 164–229, incl. the inline `anomaly?: AnomalyFacet.Result` result shape)
- Modify: `engine.ts` — method delegates: `resolveSession(token, opts) { return resolveSession(this, token, opts) }`

- [ ] **Step 1: Move the body**, `this.` → `engine.`. Preserve every branch (tenant check, anomaly evaluation, hijack signal). Import the return-type dependencies (`Anomaly`, `AnomalyFacet`) from their new homes (`~/core/anomaly`).
- [ ] **Step 2: Delegate** from the method; `import { resolveSession as resolveSessionImpl } from './engine.resolve-session'` and call it (alias to avoid the method/function name clash).
- [ ] **Step 3: Verify** — tsc `0`; session-resolution + anomaly + hijack tests pass; suite `<N>`; biome write.
- [ ] **Step 4: Commit** — `refactor(duck-auth): extract engine.resolveSession implementation`

### Task 29: Extract constructor facet-wiring → `engine.wiring.ts`

**Files:**
- Create: `src/core/engine/engine.wiring.ts` — `export function buildFacets<…>(config, events): { sessions; identities; providers; orgs; operations; idempotency; hijack; anomaly; flows }` returning the constructed facets (bodies copied from the constructor, ~lines 96–163)
- Modify: `engine.ts` — constructor calls `buildFacets` and assigns the returned facets

- [ ] **Step 1: Move the facet construction** (everything after `this.events`/`this.transport`/`this.limiter`/`this.plugins` setup up to the flows wiring) into `buildFacets(config, events)`; return the bag. Keep `DEFAULT_*` usages via the new constants imports.
- [ ] **Step 2: Rewire the constructor** to `const f = buildFacets(config, this.events); this.sessions = f.sessions; …`. The provider slots (`_passwords/_mfa/_apiKeys`) and their getters/setters stay on the class (they're the lazy provider mechanism).
- [ ] **Step 3: Verify** — tsc `0`; full suite `<N>` (constructor path is exercised by nearly every test); biome write. Confirm `engine.ts` is now materially shorter (composition root only).
- [ ] **Step 4: Commit** — `refactor(duck-auth): extract engine facet wiring into buildFacets`

### Task 30: Retire `__hashSid` re-export + final engine tidy

**Files:** Modify `src/core/engine/engine.ts`.

- [ ] **Step 1: Assess `__hashSid`** (`export const __hashSid = sha256`, ~line 313) and the `export { SessionsFacet } from '../sessions/sessions.facet'` re-export. Grep usages:
```bash
grep -rn --include='*.ts' "__hashSid" src
grep -rn --include='*.ts' "SessionsFacet" src | grep "engine"
```
- [ ] **Step 2:** If `__hashSid` has non-test users, repoint them to `import { sha256 } from '~/core/crypto'` and delete the alias. If only tests use it, repoint the tests and delete it. Repoint the `SessionsFacet`-from-engine importers to `~/core/sessions` and drop the re-export (no shims).
- [ ] **Step 3: Verify** — tsc `0`; `grep -rn "__hashSid" src` empty; suite `<N>`; biome write.
- [ ] **Step 4: Commit** — `refactor(duck-auth): drop engine __hashSid/SessionsFacet re-export shims`

---

## Group E — Final sweep

### Task 31: Repo-wide verification + monorepo typecheck

- [ ] **Step 1: No stragglers.**
```bash
grep -rn --include='*.ts' "core/facets\|core/types" src   # empty
grep -rn --include='*.ts' -E "from '.*/(errors|events|crypto|csrf|compliance|tenant|plugin|url-validators)'" src/core | grep -vE "/(errors|events|crypto|csrf|compliance|tenant|plugin|url-validators)/" || true  # each resolves to a folder
```
- [ ] **Step 2: Full suite + types across the monorepo** (apps/examples import duck-auth):
```bash
bunx vitest run 2>&1 | tail -3          # <N> passed, 0 failed
cd ../.. && bunx turbo check-types --filter=...[HEAD]   # 0 errors
```
- [ ] **Step 3: Build** to confirm tsdown/exports still resolve:
```bash
cd packages/duck-auth && bun run build 2>&1 | tail -5
```
- [ ] **Step 4: Biome whole package.**
```bash
bunx biome check --write ./src
```
- [ ] **Step 5: Commit** any biome churn — `chore(duck-auth): biome sweep after core foldization`
- [ ] **Step 6:** Announce completion and invoke **superpowers:finishing-a-development-branch**.

---

## Self-Review Notes

- **Coverage:** every scattered piece is homed — 10 facet subjects (Tasks 1–10), 9 loose primitives (11–19), all 13 namespaces out of `types/{identity,session,provider,infra}.ts` (20–23) with `types/` deleted, the namespace audit updated (24), and the engine decomposed into wiring/strict/resolve-session + helper relocations (25–30). Final sweep (31) proves no `core/facets` / `core/types` path survives.
- **No shims:** every type move is a hard move; each task's verify grep of the retired path must be empty. Group B's "barrel" files are *subject index barrels* (the established provider-folder convention), not deprecation re-exports of a moved module.
- **Type consistency:** namespace→owner map is fixed once (Target Layout) and reused verbatim in Tasks 20–24 and the audit. Facet class names (`SessionsFacet`, `IdentitiesFacet`, `ProvidersFacet`, `OrgsFacet`, `AnomalyFacet`, `HijackFacet`, `IdempotencyFacet`, `OperationsFacet`, `M2mFacet`, `FlowsFacet`) are unchanged — only their *locations* move.
- **Behavior preserved:** no test assertion changes, only import specifiers; the refactor gate is "same pass count `N`, zero failures" recorded at Task 0. Engine Group D copies bodies verbatim (`this.`→`engine.`), asserting identical thrown errors.
- **Known real-symbol placeholders:** barrels say "use the real exported names" where the exact export list wasn't inlined (e.g. crypto/csrf helper names, `M2mFacet`, detector class names). Executor opens the moved file and copies its `export` identifiers — a 30-second lookup, not a design gap.
- **Risk hotspot:** Group C multi-namespace import lines (`import { Session, Transport }`) can't be split by a single sed; every Group C task carries an explicit hand-split step gated by a `grep … → empty` check before commit.
```
