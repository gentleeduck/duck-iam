<p align="center">
  <img src="./public/logo-dark.svg" alt="@gentleduck/iam" width="120"/>
</p>

<h1 align="center">@gentleduck/iam</h1>

<p align="center">
  Type-safe RBAC + ABAC + ReBAC authorization engine with policy explain, devtools, and framework adapters.
</p>

<p align="center">
  <a href="./LICENSE">MIT</a> -
  <a href="./CHANGELOG.md">Changelog</a> -
  <a href="./CONTRIBUTING.md">Contributing</a> -
  <a href="https://gentleduck.org/duck-iam">Docs</a>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@gentleduck/iam"><img src="https://img.shields.io/npm/v/@gentleduck/iam.svg" alt="npm"/></a>
  <a href="https://www.npmjs.com/package/@gentleduck/iam"><img src="https://img.shields.io/npm/dm/@gentleduck/iam.svg" alt="downloads"/></a>
  <a href="./LICENSE"><img src="https://img.shields.io/npm/l/@gentleduck/iam.svg" alt="MIT"/></a>
</p>

---

## Install

```sh
bun add @gentleduck/iam
```

## Quick start

```ts
import { iam } from '@gentleduck/iam'

const engine = iam({
  roles: {
    owner: ['*'],
    editor: ['post:read', 'post:write'],
    reader: ['post:read'],
  },
})

const result = engine.can({ user: { roles: ['editor'] }, action: 'post:write' })
// { allowed: true, reason: 'role:editor grants post:write' }
```

## Workspace

| Path | Package | Role |
| --- | --- | --- |
| [`packages/duck-iam`](packages/duck-iam) | [`@gentleduck/iam`](https://www.npmjs.com/package/@gentleduck/iam) | Core policy engine, RBAC + ABAC + ReBAC, devtools (`@gentleduck/iam/dt`) |

### Adapters (subpath exports of `@gentleduck/iam`)

| Subpath | Target |
| --- | --- |
| `@gentleduck/iam/server/next` | Next.js App Router |
| `@gentleduck/iam/server/express` | Express |
| `@gentleduck/iam/server/nest` | NestJS |
| `@gentleduck/iam/server/hono` | Hono |
| `@gentleduck/iam/server/generic` | Framework-agnostic |
| `@gentleduck/iam/client/react` | React hooks |
| `@gentleduck/iam/client/vue` | Vue composables |
| `@gentleduck/iam/client/vanilla` | DOM-free client |
| `@gentleduck/iam/adapters/memory` | In-memory store |
| `@gentleduck/iam/adapters/file` | File-backed store |
| `@gentleduck/iam/adapters/prisma` | Prisma |
| `@gentleduck/iam/adapters/drizzle` | Drizzle (pg / mysql / sqlite) |
| `@gentleduck/iam/adapters/redis` | Redis |
| `@gentleduck/iam/adapters/http` | Remote PDP over HTTP |
| `@gentleduck/iam/invalidators/redis` | Redis pub/sub invalidator |
| `@gentleduck/iam/observability/metrics` | Prometheus / OTel metrics |
| `@gentleduck/iam/dt` | Devtools UI panel |

## Examples

| Path | Stack |
| --- | --- |
| [`examples/blogduck`](examples/blogduck) | Next.js + Prisma blog with editor/reader roles |
| [`examples/docduck`](examples/docduck) | Next.js + Hocuspocus collaborative docs |
| [`examples/tanstack-start`](examples/tanstack-start) | TanStack Start app w/ posthog + iam |
| [`examples/vite`](examples/vite) | Vite + React minimal demo |

## Build

```sh
bun install
bunx turbo run build --filter='./packages/*'
bunx turbo run test --filter='./packages/*'
bunx turbo run check-types --filter='./packages/*'
```

## Docs

- Site: [gentleduck.org/duck-iam](https://gentleduck.org/duck-iam)
- Devtools: import `@gentleduck/iam/dt` to inspect policy evaluation in your app
- Sibling repos: [`@gentleduck/ui`](https://github.com/gentleeduck/duck-ui), [`@gentleduck/upload`](https://github.com/gentleeduck/duck-upload), [`@gentleduck/md`](https://github.com/gentleeduck/duck-md)

## Contributing

PR checklist + style notes in [`CONTRIBUTING.md`](CONTRIBUTING.md).
Security: [`SECURITY.md`](SECURITY.md). Behaviour: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## License

MIT. See [`LICENSE`](LICENSE).
