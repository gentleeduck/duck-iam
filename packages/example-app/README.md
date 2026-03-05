# duck-iam Example App

Full working example showing duck-iam with Next.js (App Router), Express,
Hono/Cloudflare Workers, React client components, and Prisma/Drizzle.

## Quick Start

```bash
# 1. Install dependencies (from monorepo root)
bun install

# 2. Set up your database
echo 'DATABASE_URL="postgresql://user:pass@localhost:5432/myapp"' > .env

# 3. Run the migration
bunx prisma migrate dev --name access_engine

# 4. Seed roles, policies, and test users
bun prisma/seed.ts

# 5. Start the app
bun run dev
```

## Migration Steps

### Option A: Prisma

```bash
# The schema already includes duck-iam tables.
# Just run migrate:
bunx prisma migrate dev --name access_engine
bunx prisma generate
```

This creates 4 tables:
- `access_policies` — ABAC policy rules (JSON)
- `access_roles` — RBAC role definitions (JSON)
- `access_assignments` — user→role mappings
- `access_subject_attrs` — user ABAC attributes (JSON)

### Option B: Drizzle

```bash
# Use the schema in src/db/drizzle-schema.ts
bunx drizzle-kit generate
bunx drizzle-kit migrate
```

### Option C: Raw SQL

```bash
# Apply the migration directly:
psql $DATABASE_URL < prisma/migrations/001_access_engine/migration.sql
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Next.js App                       │
│                                                      │
│  ┌──────────────┐   ┌───────────────────────────┐   │
│  │ layout.tsx    │   │ Client Components          │   │
│  │ (RSC)        │   │                            │   │
│  │              │   │  <Can action="create"       │   │
│  │ Generates    │──>│       resource="post">      │   │
│  │ PermissionMap│   │    <NewPostButton />        │   │
│  │              │   │  </Can>                     │   │
│  └──────┬───────┘   │                            │   │
│         │           │  const { can } = useAccess()│   │
│         │           └───────────────────────────┘   │
│         │                                           │
│  ┌──────▼───────────────────────────────────────┐   │
│  │ API Routes / Server Actions                   │   │
│  │                                               │   │
│  │  withAccess(engine, "delete", "post", handler)│   │
│  │  engine.can(userId, "update", resource)       │   │
│  └──────┬───────────────────────────────────────┘   │
│         │                                           │
├─────────┼───────────────────────────────────────────┤
│         │           duck-iam                    │
│  ┌──────▼───────┐                                   │
│  │    Engine     │──> evaluate() (pure, stateless)   │
│  │              │──> rolesToPolicy() (RBAC→ABAC)    │
│  │  cache(LRU)  │──> conditions (AND/OR/NONE)       │
│  └──────┬───────┘                                   │
│         │                                           │
│  ┌──────▼───────┐                                   │
│  │ PrismaAdapter│ (or DrizzleAdapter, MemoryAdapter)│
│  └──────┬───────┘                                   │
│         │                                           │
├─────────┼───────────────────────────────────────────┤
│         │                                           │
│  ┌──────▼───────┐                                   │
│  │  PostgreSQL   │                                   │
│  │              │                                   │
│  │ access_policies      (ABAC rules as JSON)        │
│  │ access_roles         (RBAC defs as JSON)         │
│  │ access_assignments   (user→role)                 │
│  │ access_subject_attrs (user attributes)           │
│  └──────────────┘                                   │
└─────────────────────────────────────────────────────┘
```

## File Guide

### Setup & Config
| File | Purpose |
|------|---------|
| `prisma/schema.prisma` | DB schema (your tables + duck-iam tables) |
| `prisma/migrations/001_access_engine/migration.sql` | Raw SQL migration |
| `prisma/seed.ts` | Seeds roles, policies, and test users |
| `src/lib/prisma.ts` | Prisma client singleton |
| `src/lib/access.ts` | **Central config**: roles, policies, engine instance |
| `src/lib/access-client.tsx` | React hooks/components factory |
| `src/lib/auth.ts` | Auth helpers (replace with your auth) |
| `src/lib/sync-attributes.ts` | Sync user data → duck-iam attributes |

### Backend (Server)
| File | Purpose |
|------|---------|
| `src/app/api/posts/[id]/route.ts` | Next.js API route with `withAccess()` |
| `src/app/api/me/permissions/route.ts` | Returns PermissionMap for the client |
| `src/middleware.ts` | Next.js edge middleware |
| `src/api/express-server.ts` | Standalone Express server with `guard()` |
| `src/api/hono-worker.ts` | Hono + Cloudflare Workers + Drizzle |

### Frontend (Client)
| File | Purpose |
|------|---------|
| `src/app/layout.tsx` | RSC: generates permissions, hydrates `<AccessProvider>` |
| `src/app/posts/[id]/page.tsx` | RSC: server-side per-resource checks |
| `src/components/sidebar.tsx` | Client: `<Can>`, `<Cannot>`, `useAccess()` |
| `src/components/post-actions.tsx` | Client: buttons gated by server-computed perms |

### Alternative DB (Drizzle)
| File | Purpose |
|------|---------|
| `src/db/drizzle-schema.ts` | Drizzle table definitions |

## Key Patterns

### 1. Two-layer permission checking

**Server-side** (in layout.tsx): Generate a broad PermissionMap for common checks.
```tsx
const perms = await getPermissions(engine, userId, STANDARD_CHECKS);
```

**Server-side** (in page/route): Do resource-specific checks with attributes.
```tsx
const canEdit = await engine.can(userId, "update", {
  type: "post",
  id: post.id,
  attributes: { ownerId: post.authorId },
});
```

**Client-side**: Instant UI gating from the hydrated map.
```tsx
<Can action="create" resource="post">
  <NewPostButton />
</Can>
```

### 2. Attribute sync

When user data changes, sync to duck-iam:
```ts
await syncUserAttributes(userId);
```

This keeps ABAC attributes (plan, org status, flags) in sync with your app.

### 3. Roles define base access, policies add constraints

Roles are additive (what you CAN do). Policies are subtractive (what you CAN'T do).
A user with the "editor" role can edit posts, but the "suspended-org" policy
blocks them if their org is suspended. Deny always wins.

## Test It

```bash
# Alice (admin/enterprise) - should see everything
curl -H "Authorization: Bearer user-alice" http://localhost:3001/api/me/permissions

# Dave (viewer/free) - should see almost nothing
curl -H "Authorization: Bearer user-dave" http://localhost:3001/api/me/permissions

# Dave tries to create a post - should get 403
curl -X POST -H "Authorization: Bearer user-dave" \
  -H "Content-Type: application/json" \
  -d '{"title":"test","body":"test"}' \
  http://localhost:3001/api/posts

# Bob (editor) tries analytics - should work (pro plan)
curl -H "Authorization: Bearer user-bob" http://localhost:3001/api/analytics

# Dave tries analytics - should get 403 (free plan)
curl -H "Authorization: Bearer user-dave" http://localhost:3001/api/analytics
```
