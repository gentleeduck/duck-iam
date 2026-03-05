# duck-iam Docs + Internal Package Migration Plan

## Goal
Migrate `apps/duck-iam-docs` and related workspace setup to match the current gentleduck docs stack and package conventions used in `@duck-ui`, while safely upgrading published `@gentleduck/*` dependencies.

## Current State (Observed)
- Docs app already uses `@gentleduck/docs` (`velite.config.ts` imports `docsVeliteConfig`).
- Docs app still imports legacy registry package names:
  - `@gentleduck/registry-ui-duckui`
  - `@gentleduck/registry-blocks-duckui`
  - `@gentleduck/registry-examples-duckui`
- `apps/duck-iam-docs/package.json` uses older published package versions:
  - `@gentleduck/docs`: `^0.0.13`
  - `@gentleduck/lazy`: `^1.2.9`
  - `@gentleduck/libs`: `^0.1.11`
  - `@gentleduck/motion`: `^0.1.13`
  - `@gentleduck/vim`: `^0.1.12`
- Current versions in `@duck-ui` are newer:
  - `@gentleduck/docs`: `0.0.14`
  - `@gentleduck/lazy`: `1.2.10`
  - `@gentleduck/libs`: `0.1.12`
  - `@gentleduck/motion`: `0.1.14`
  - `@gentleduck/vim`: `0.1.13`
  - `@gentleduck/registry-ui`: `0.2.1`

## Target State
1. `duck-iam-docs` uses current package names and versions aligned with the active gentleduck ecosystem.
2. Docs build/runtime conventions match the current `@duck-ui` setup (where applicable).
3. No unresolved registry component imports and no broken docs routes.
4. Build/test/type-check pipelines are stable after migration.

## Scope
- `apps/duck-iam-docs/*`
- root workspace config (`package.json`, lockfile, ts/biome/turbo integration where needed)
- dependency version harmonization for published `@gentleduck/*` packages used by docs app

## Out of Scope
- Rewriting all docs content semantics.
- Deep redesign of site branding/visual identity.
- Major API changes in `packages/duck-iam` (unless required to unblock docs examples).

## Phase Plan

### Phase 1: Baseline + Safety
1. Create a migration branch in `@duck-iam`.
2. Snapshot current behavior:
   - `bun run check-types`
   - `bun run build` at root
   - `bun run build` in `apps/duck-iam-docs`
3. Capture known warnings/errors before changes.

### Phase 2: Package Upgrade Matrix
Update `apps/duck-iam-docs/package.json`:
1. Upgrade published shared packages:
   - `@gentleduck/docs` -> `^0.0.14`
   - `@gentleduck/lazy` -> `^1.2.10`
   - `@gentleduck/libs` -> `^0.1.12`
   - `@gentleduck/motion` -> `^0.1.14`
   - `@gentleduck/vim` -> `^0.1.13`
2. Replace legacy registry package name:
   - `@gentleduck/registry-ui-duckui` -> `@gentleduck/registry-ui` (version `^0.2.1` or compatible)
3. Reinstall lockfile (`bun install`) and resolve peer/version issues.

### Phase 3: Import + Source Path Migration
1. Replace imports in docs app:
   - `@gentleduck/registry-ui-duckui/*` -> `@gentleduck/registry-ui/*`
2. Update Tailwind source globs in `app/globals.css`:
   - remove `*-duckui` paths
   - point to current package names
3. Update `next.config.ts` `transpilePackages` to match new package names.

### Phase 4: Docs Runtime Alignment
1. Compare `duck-iam-docs` app shell with current `@duck-ui` docs shell:
   - provider order
   - theme/meta config wiring
   - docs entry mapping from `.velite`
2. Keep IAM-specific site config and nav, but align infrastructure patterns.
3. Ensure docs routes remain stable:
   - `/docs`
   - `/docs/course/*`
   - OG/sitemap generation

### Phase 5: MDX + Course Quality Pass
1. Validate MDX frontmatter and structure in `content/docs/**`.
2. Normalize code blocks/components to current docs conventions.
3. Review course chapters for:
   - broken links
   - stale package names
   - inconsistent command snippets

### Phase 6: CI/Tooling Hardening
1. Add/verify docs app scripts:
   - `check-types`
   - `build:docs`
   - `build`
2. Confirm root `turbo` pipeline includes docs checks.
3. Add or tighten regression checks for docs routing/build if missing.

### Phase 7: Release + Verification
1. Run full verification:
   - root: `bun run check-types`, `bun run build`
   - docs app: `bun run check-types`, `bun run build`
2. Smoke-test critical pages in dev/prod mode.
3. Prepare migration PR with changelog notes.

## Risks and Controls
- Risk: package rename causes unresolved imports.
  - Control: scripted import replacement + `rg` verification pass.
- Risk: Tailwind source paths miss classes after rename.
  - Control: audit `@source` directives and visually verify key components.
- Risk: docs build regressions from updated `@gentleduck/docs`.
  - Control: phase rollout + compile checks after each phase.
- Risk: lockfile/version drift in monorepo.
  - Control: single `bun install` after dependency edits + commit lockfile once.

## Execution Checklist
- [ ] Phase 1 baseline run completed and recorded
- [ ] Package versions upgraded
- [ ] Legacy `*-duckui` package names removed
- [ ] `globals.css` source paths migrated
- [ ] `next.config.ts` transpile list migrated
- [ ] Docs routes + course pages smoke-tested
- [ ] Root and app builds green
- [ ] PR opened with migration summary

## Suggested Commit Strategy
1. `chore(docs): upgrade shared @gentleduck package versions`
2. `refactor(docs): migrate registry-ui-duckui imports to registry-ui`
3. `chore(docs): align next/tailwind docs infrastructure`
4. `docs(course): update course/content links and command snippets`
5. `chore(ci): enforce docs build/type checks`
