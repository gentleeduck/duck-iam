# CLAUDE.md

## React Grab

This project uses [React Grab](https://github.com/anthropics/react-grab) as a dev tool. When the user references a UI element selected via React Grab, trust the element selection — it includes accurate component names, file paths, and prop details from the running React tree.

## Monorepo Structure

- `apps/duck-iam-docs` — Next.js documentation site
- `packages/duck-iam` — Core duck-iam package
- `packages/ui` — Shared UI components
- `tooling/` — Shared tooling configs
- `examples/` — Example apps

## Build Commands

This project uses **bun** as the package manager and **turbo** for task orchestration.

```sh
bun install          # Install dependencies
bun run dev          # Start dev servers (turbo)
bun run build        # Build all packages (turbo)
bun run test         # Run tests (turbo)
bun run check        # Biome check
bun run lint         # Biome lint
bun run format       # Biome format (write)
bun run fix          # Biome check + auto-fix
bun run check-types  # TypeScript type checking (turbo)
```

## Coding Conventions

- **Formatting/Linting**: Biome is used for formatting and linting (not ESLint/Prettier). Run `bun run fix` to auto-fix.
- **TypeScript**: Strict TypeScript throughout. Use explicit types for function signatures and exports.
- **Imports**: Use path aliases (e.g., `~/config/docs`) within apps. Use package names (`@gentleduck/...`) for cross-package imports.
- **Components**: React functional components only. Use `cn()` from `@gentleduck/libs/cn` for className merging.
- **Styles**: Tailwind CSS v4. No inline style objects unless necessary.
- **Commits**: Use conventional commits (`feat:`, `fix:`, `chore:`, etc.).
