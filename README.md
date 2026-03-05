# duck-iam

Modern ABAC/RBAC access control engine for TypeScript. Framework-agnostic core with integrations for Express, NestJS, Hono, Next.js, React, and Vue.

## Documentation
<<<<<<< HEAD
- GitHub: https://github.com/gentleeduck/duck-ui
=======
- Website: https://gen.gentleduck.org
- GitHub: https://github.com/gentleeduck/duck-gen
>>>>>>> 68028f2b8f071c10853ff31e15c817d8fd06f964

## What's in the repo

### Packages
- `packages/duck-iam` — `duck-iam` core library (RBAC + ABAC + hybrid)
- `packages/example-shared` — shared access config, types, and DB schema for examples
- `packages/example-api` — NestJS backend example with typed `@Authorize()` decorators
- `packages/example-app` — Next.js frontend example with `<Can>` / `useAccess()` components

### Apps
- `apps/duck-iam-docs` — documentation site

## Features
- Type-safe RBAC with role inheritance
- Attribute-based access control (ABAC) with 17 condition operators
- Hybrid RBAC + ABAC in a single evaluation pipeline
- Hierarchical resources via dot-notation (`dashboard.users.settings`)
- Scoped permissions (`system`, `tenant`)
- 4 combining algorithms: deny-overrides, allow-overrides, first-match, highest-priority
- Adapters: Memory, Prisma, Drizzle, HTTP
- Server integrations: Express, NestJS, Hono, Next.js
- Client libraries: React, Vue, vanilla JS
- Compile-time type checking for actions, resources, scopes, and roles

## Getting Started
```bash
<<<<<<< HEAD
git clone https://github.com/gentleeduck/duck-ui.git
cd duck-ui
=======
git clone https://github.com/gentleeduck/duck-gen.git
cd duck-gen
>>>>>>> 68028f2b8f071c10853ff31e15c817d8fd06f964
bun install
```

## Build
```bash
bun run build
```

## Run examples
```bash
# Start the NestJS API
cd packages/example-api && bun run start:dev

# Start the Next.js app
cd packages/example-app && bun run dev
```

## Contributing
We welcome contributions. Please read [`CONTRIBUTING.md`](./CONTRIBUTING.md) and [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md).

## License
MIT. See [`LICENSE`](./LICENSE) for more information.
