<p align="center">
  <img src="./public/logo-dark.svg" alt="gentleduck/iam + auth" width="120"/>
</p>

<h1 align="center">@gentleduck/iam</h1>

<p align="center">
  Authentication and authorization for TypeScript. Framework-agnostic. Batteries included. No hosted plane.
</p>

<p align="center">
  <a href="./LICENSE">MIT</a> -
  <a href="./CHANGELOG.md">Changelog</a> -
  <a href="./CONTRIBUTING.md">Contributing</a> -
  <a href="https://gentleduck.org">Docs</a>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@gentleduck/auth"><img src="https://img.shields.io/npm/v/@gentleduck/auth.svg?label=auth" alt="auth"/></a>
  <a href="https://www.npmjs.com/package/@gentleduck/iam"><img src="https://img.shields.io/npm/v/@gentleduck/iam.svg?label=iam" alt="iam"/></a>
  <a href="./LICENSE"><img src="https://img.shields.io/npm/l/@gentleduck/iam.svg" alt="MIT"/></a>
</p>

---

## Install

```sh
bun add @gentleduck/auth @gentleduck/iam
```

## Quick start

```ts
import { defineAuth }         from '@gentleduck/auth/core'
import { createAccessConfig } from '@gentleduck/iam/core'

const auth   = defineAuth({ /* baseUrl, storage, providers */ })
const access = createAccessConfig({ actions, resources, roles })
const engine = access.createEngine({ adapter })

const session = await auth.flows.signIn({ providerId: 'password', input })
const allowed = await engine.can(session.session!.identityId, 'update', { type: 'post' })
```

## Workspace

| Path | Package | Role |
| --- | --- | --- |
| [`packages/duck-auth`](packages/duck-auth) | [`@gentleduck/auth`](https://www.npmjs.com/package/@gentleduck/auth) | **AuthN** - sessions, passwords, magic-link, passkeys, OAuth, SAML, MFA, JWT, webhooks |
| [`packages/duck-iam`](packages/duck-iam) | [`@gentleduck/iam`](https://www.npmjs.com/package/@gentleduck/iam) | **AuthZ** - RBAC + ABAC + ReBAC policy engine with explain trace + devtools |

Both packages have their own subpath export tree (providers, transports, adapters, server middleware, clients, channels, tooling). See each package's README for the full list.

## Apps

| Path | Role |
| --- | --- |
| [`apps/duck-auth-demo`](apps/duck-auth-demo) | End-to-end `@gentleduck/auth` reference: password + magic-link + OAuth + passkey + MFA on Postgres + Hono + Storybook UI |
| [`apps/duck-iam-docs`](apps/duck-iam-docs) | Docs site at [gentleduck.org/duck-iam](https://gentleduck.org/duck-iam) |

## Examples

| Path | Stack |
| --- | --- |
| [`examples/blogduck`](examples/blogduck) | Next.js + Prisma blog with `@gentleduck/iam` roles |
| [`examples/docduck`](examples/docduck) | Collaborative docs (Hocuspocus + Next.js) |
| [`examples/tanstack-start`](examples/tanstack-start) | TanStack Start + posthog |
| [`examples/vite`](examples/vite) | Vite + React minimal demo |

## Build

```sh
bun install
bunx turbo run build --filter='./packages/*'
bunx turbo run test --filter='./packages/*'
bunx turbo run check-types --filter='./packages/*'
```

## Docs

- Site: [gentleduck.org](https://gentleduck.org) - auth at [`/duck-auth`](https://gentleduck.org/duck-auth), iam at [`/duck-iam`](https://gentleduck.org/duck-iam)
- Devtools: import `@gentleduck/iam/dt` to inspect policy evaluation inside your app
- Sibling repos: [`@gentleduck/ui`](https://github.com/gentleeduck/duck-ui), [`@gentleduck/upload`](https://github.com/gentleeduck/duck-upload), [`@gentleduck/md`](https://github.com/gentleeduck/duck-md)

## Contributing

PR checklist + style notes in [`CONTRIBUTING.md`](CONTRIBUTING.md).
Security: [`SECURITY.md`](SECURITY.md). Behaviour: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## License

MIT. See [`LICENSE`](LICENSE).
