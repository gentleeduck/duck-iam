# duck-auth docs

Content-only docs app: `content/docs/**` is consumed by the docs site build, not built here. This package's own job is generating the API reference.

## Regenerating the API reference

```sh
bun run docs:api                              # from this directory
bun run --cwd docs/duck-auth-docs docs:api    # from the repo root
```

Runs [TypeDoc](https://typedoc.org) with `typedoc-plugin-markdown` over every `exports` entry point of `packages/duck-auth`, writes `content/docs/api/generated/`, then converts it to `.mdx`. The generated files are output: a wrong description is fixed in the JSDoc in `packages/duck-auth/src`. `content/docs/api/index.mdx` is hand-written and lives outside `generated/`, so a regeneration never touches it.

The workspace pins TypeScript 7, which has no programmatic compiler API, so this package pins its own `typescript@^5.9.3`. `docs:api` sets `NODE_OPTIONS` to register `scripts/ts5-hook.mjs`, which points only TypeDoc's `import 'typescript'` at that copy. `skipErrorChecking` keeps TypeDoc reading past diagnostics 5.9 reports and 7 does not; `bun run check-types` at the repo root is the type gate.

## Syncing to @duck-ui

`content/docs/**` is the source of truth. `bun run sync-docs` from the repo root copies it into the sibling `@duck-ui` checkout at `apps/duck/content/docs/duck-auth/`, backing up what was there first. Edit docs here: a direct edit in `@duck-ui` is overwritten by the next sync.
