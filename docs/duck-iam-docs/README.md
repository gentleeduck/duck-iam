# duck-iam docs

Content-only docs app: `content/docs/**` is consumed by the docs site build, not built here.
This package's own job is generating the API reference.

## Regenerating the API reference

```sh
bun run docs:api          # from this directory
bun run --cwd docs/duck-iam-docs docs:api   # from the repo root
```

Runs [TypeDoc](https://typedoc.org) + `typedoc-plugin-markdown` against `packages/duck-iam/src`
and writes plain `.md` files into `content/docs/api/generated/`, then converts them to `.mdx`.
Those files are generated output, not hand-edited — a wrong description means the JSDoc comment
in `packages/duck-iam/src` is wrong, not the generated file.

### Why `docs:api` sets `NODE_OPTIONS`

This workspace pins TypeScript 7, which doesn't expose the programmatic compiler API yet (ships
the `tsc` binary only). TypeDoc needs that API, so this package pins its own `typescript@^5.9.3`.
`typedoc` itself hoists to the workspace root `node_modules`, though, so a plain run resolves the
workspace's TS 7 instead of the local 5.9.3 anyway — `scripts/ts5-hook.mjs` is a Node module
resolution hook (registered via `scripts/register-ts5-hook.mjs`) that redirects just `typedoc`'s
`import 'typescript'` to this package's own nested copy, without touching resolution anywhere
else in the workspace.

### Why `typedoc.json` sets `skipErrorChecking`

TypeDoc builds the program from `tsconfig.typedoc.json` (the package's own tsconfig, minus test
files) using the pinned TS 5.9.3, not TS 7. A couple of generic-inference cases that TS 7 accepts
still report as errors under 5.9 (`http/index.ts`'s `iamAsScopeLiteral` call, `dt/panels/subjects.tsx`'s
`attempt` callback) — `bun run check-types` at the repo root is the real gate and is clean under
TS 7. `skipErrorChecking` tells TypeDoc to keep reading declarations past these version-specific
diagnostics rather than treat them as fatal.

## Syncing to @duck-ui

`content/docs/**` here is the source of truth. Running `bun run sync-docs` from the repo root
copies every `.mdx` file into the sibling `@duck-ui` checkout's docs site
(`apps/duck/content/docs/duck-iam/`), backing up whatever was there first. Edit docs here, not
directly in `@duck-ui` — a direct edit there is overwritten by the next sync.
