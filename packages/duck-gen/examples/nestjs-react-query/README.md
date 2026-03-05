# Duck Gen + NestJS + React Query + i18n Example

This example shows Duck Gen generating API route and message types from a
NestJS server, then consuming those types in a React client using Duck Query,
React Query, and a typed i18n dictionary.

## Setup

```bash
cd packages/duck-gen/examples/nestjs-react-query
bun install
```

## Generate types

```bash
bun run gen
```

## Run

```bash
# Server
cd server && bun run dev

# Client (in another terminal)
cd client && bun run dev
```

By default, the client expects the API at `http://localhost:3000`.
You can override it with `VITE_API_BASE`.
