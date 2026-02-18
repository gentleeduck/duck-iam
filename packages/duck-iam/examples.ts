// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// access-engine: Complete Usage Examples
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

import { defineRole, Engine, MemoryAdapter, type PermissionCheck, policy } from './src'

// ═══════════════════════════════════════════════
// 1. PURE RBAC
// ═══════════════════════════════════════════════

async function pureRBAC() {
  const viewer = defineRole('viewer').name('Viewer').grantRead('post', 'comment', 'profile').build()

  const editor = defineRole('editor').name('Editor').inherits('viewer').grantCRUD('post').grantCRUD('comment').build()

  const admin = defineRole('admin').name('Admin').inherits('editor').grantAll('user').grantAll('settings').grantAll('billing').build()

  const engine = new Engine({
    adapter: new MemoryAdapter({
      roles: [viewer, editor, admin],
      assignments: {
        alice: ['admin'],
        bob: ['editor'],
        carol: ['viewer'],
      },
    }),
  })

  console.log(await engine.can('alice', 'delete', { type: 'user', attributes: {} })) // true
  console.log(await engine.can('bob', 'create', { type: 'post', attributes: {} })) // true
  console.log(await engine.can('bob', 'delete', { type: 'user', attributes: {} })) // false
  console.log(await engine.can('carol', 'read', { type: 'post', attributes: {} })) // true
  console.log(await engine.can('carol', 'create', { type: 'post', attributes: {} })) // false
}

// ═══════════════════════════════════════════════
// 2. PURE ABAC (Cloudflare-style attribute policies)
// ═══════════════════════════════════════════════

async function pureABAC() {
  const contentPolicy = policy('content-access')
    .name('Content Access Control')
    .algorithm('deny-overrides')

    // Owners can edit their own resources
    .rule('owner-edit', (r) =>
      r
        .allow()
        .on('update', 'delete')
        .of('post', 'comment')
        .when((w) => w.isOwner()),
    )

    // Premium users access premium content
    .rule('premium-gate', (r) =>
      r
        .allow()
        .on('read')
        .of('premium-article')
        .when((w) => w.attr('plan', 'in', ['premium', 'enterprise'])),
    )

    // Suspended orgs blocked from everything (high priority deny)
    .rule('suspended-block', (r) =>
      r
        .deny()
        .on('*')
        .of('*')
        .priority(100)
        .when((w) => w.attr('orgStatus', 'eq', 'suspended')),
    )

    // Geo-restricted content
    .rule('geo-restrict', (r) =>
      r
        .deny()
        .on('read')
        .of('restricted-content')
        .when((w) => w.env('country', 'in', ['KP', 'IR', 'CU'])),
    )

    // Time-based deploy restriction
    .rule('deploy-window', (r) =>
      r
        .allow()
        .on('deploy')
        .of('production')
        .when((w) => w.attr('department', 'in', ['engineering', 'devops']).env('hour', 'gte', 9).env('hour', 'lte', 17)),
    )

    .build()

  const engine = new Engine({
    adapter: new MemoryAdapter({
      policies: [contentPolicy],
      attributes: {
        alice: { plan: 'premium', orgStatus: 'active' },
        bob: { plan: 'free', orgStatus: 'active' },
        charlie: { plan: 'enterprise', orgStatus: 'suspended' },
      },
    }),
  })

  console.log(
    await engine.can('alice', 'read', {
      type: 'premium-article',
      attributes: {},
    }),
  )
  // true

  console.log(
    await engine.can('bob', 'read', {
      type: 'premium-article',
      attributes: {},
    }),
  )
  // false

  // Suspended user blocked even though enterprise plan
  console.log(
    await engine.can('charlie', 'read', {
      type: 'premium-article',
      attributes: {},
    }),
  )
  // false
}

// ═══════════════════════════════════════════════
// 3. HYBRID RBAC + ABAC
// ═══════════════════════════════════════════════

async function hybrid() {
  // RBAC: base permissions
  const member = defineRole('member')
    .name('Team Member')
    .grant('read', 'project')
    .grant('create', 'task')
    // Members can only update their own tasks (ABAC condition on RBAC)
    .grantWhen('update', 'task', (w) => w.isOwner())
    .build()

  const lead = defineRole('lead')
    .name('Team Lead')
    .inherits('member')
    .grant('update', 'task') // leads update any task
    .grant('delete', 'task')
    .build()

  // ABAC: cross-cutting security policies
  const security = policy('security')
    .algorithm('deny-overrides')

    .rule('ip-fence', (r) =>
      r
        .deny()
        .on('*')
        .of('secrets', 'billing')
        .priority(100)
        .when((w) => w.env('ip', 'not_contains', '10.0.')),
    )

    .rule('mfa-required', (r) =>
      r
        .deny()
        .on('update', 'delete')
        .of('production')
        .priority(90)
        .when((w) => w.attr('mfaEnabled', 'eq', false)),
    )

    .build()

  const engine = new Engine({
    adapter: new MemoryAdapter({
      roles: [member, lead],
      policies: [security],
      assignments: {
        alice: ['lead'],
        bob: ['member'],
      },
      attributes: {
        alice: { mfaEnabled: true },
        bob: { mfaEnabled: false },
      },
    }),
    hooks: {
      onDeny: (req, decision) => {
        console.log(`DENIED: ${req.subject.id} → ${req.action}:${req.resource.type} | ${decision.reason}`)
      },
    },
  })

  // Lead can update any task
  console.log(
    await engine.can('alice', 'update', {
      type: 'task',
      attributes: { ownerId: 'bob' },
    }),
  )
  // true

  // Member can only update own tasks
  console.log(
    await engine.can('bob', 'update', {
      type: 'task',
      attributes: { ownerId: 'bob' },
    }),
  )
  // true

  console.log(
    await engine.can('bob', 'update', {
      type: 'task',
      attributes: { ownerId: 'alice' },
    }),
  )
  // false
}

// ═══════════════════════════════════════════════
// 4. BATCH PERMISSIONS (for UI rendering)
// ═══════════════════════════════════════════════

async function batchCheck() {
  const engine = new Engine({
    adapter: new MemoryAdapter({
      roles: [defineRole('editor').grantCRUD('post').grantRead('analytics').build()],
      assignments: { alice: ['editor'] },
    }),
  })

  const checks: PermissionCheck[] = [
    { action: 'create', resource: 'post' },
    { action: 'read', resource: 'post' },
    { action: 'delete', resource: 'post' },
    { action: 'manage', resource: 'user' },
    { action: 'read', resource: 'analytics' },
    { action: 'access', resource: 'billing' },
  ]

  const perms = await engine.permissions('alice', checks)
  console.log(perms)
  // {
  //   "create:post": true,
  //   "read:post": true,
  //   "delete:post": true,
  //   "manage:user": false,
  //   "read:analytics": true,
  //   "access:billing": false,
  // }
}

// ═══════════════════════════════════════════════
// 5. EXPRESS INTEGRATION
// ═══════════════════════════════════════════════

/*
import express from "express";
import { Engine } from "access-engine";
import { PrismaAdapter } from "access-engine/adapters/prisma";
import { accessMiddleware, guard } from "access-engine/server/express";

const engine = new Engine({
  adapter: new PrismaAdapter(prisma),
  cacheTTL: 30,
});

const app = express();

// Option A: Global middleware (checks every route)
app.use(accessMiddleware(engine, {
  getUserId: (req) => req.user?.id,
}));

// Option B: Per-route guards (more granular)
app.get("/posts", handler);
app.post("/posts", guard(engine, "create", "post"), handler);
app.delete("/posts/:id", guard(engine, "delete", "post"), handler);
app.post("/admin/users", guard(engine, "manage", "user"), handler);
*/

// ═══════════════════════════════════════════════
// 6. NESTJS INTEGRATION
// ═══════════════════════════════════════════════

/*
import { Module, Controller, Delete, Param, UseGuards, Injectable, CanActivate, ExecutionContext, Inject } from "@nestjs/common";
import { Engine } from "access-engine";
import { PrismaAdapter } from "access-engine/adapters/prisma";
import { Authorize, nestAccessGuard, createEngineProvider, ACCESS_ENGINE_TOKEN } from "access-engine/server/nest";

// --- Module ---
@Module({
  providers: [
    createEngineProvider(() => new Engine({ adapter: new PrismaAdapter(prisma) })),
    AccessGuard,
  ],
})
export class AppModule {}

// --- Guard ---
@Injectable()
class AccessGuard implements CanActivate {
  private checker: ReturnType<typeof nestAccessGuard>;

  constructor(@Inject(ACCESS_ENGINE_TOKEN) engine: Engine) {
    this.checker = nestAccessGuard(engine, {
      getUserId: (req) => req.user?.sub,
    });
  }

  canActivate(context: ExecutionContext) {
    return this.checker(context);
  }
}

// --- Controller ---
@Controller("posts")
@UseGuards(AccessGuard)
class PostsController {
  @Delete(":id")
  @Authorize({ action: "delete", resource: "post" })
  async deletePost(@Param("id") id: string) {
    // Only runs if authorized
  }

  @Get()
  @Authorize({ infer: true }) // infers action=read, resource=posts
  async listPosts() {}
}
*/

// ═══════════════════════════════════════════════
// 7. HONO (Cloudflare Workers / Bun / Deno)
// ═══════════════════════════════════════════════

/*
import { Hono } from "hono";
import { Engine } from "access-engine";
import { DrizzleAdapter } from "access-engine/adapters/drizzle";
import { accessMiddleware, guard } from "access-engine/server/hono";

const engine = new Engine({ adapter: new DrizzleAdapter(drizzleConfig) });
const app = new Hono();

// Global
app.use("/*", accessMiddleware(engine, {
  getUserId: (c) => c.get("userId"),
}));

// Per-route
app.delete("/posts/:id", guard(engine, "delete", "post"), (c) => {
  return c.json({ deleted: true });
});
*/

// ═══════════════════════════════════════════════
// 8. NEXT.JS APP ROUTER
// ═══════════════════════════════════════════════

/*
// --- lib/access.ts ---
import { Engine } from "access-engine";
import { PrismaAdapter } from "access-engine/adapters/prisma";
export const engine = new Engine({ adapter: new PrismaAdapter(prisma) });

// --- app/api/posts/[id]/route.ts ---
import { withAccess } from "access-engine/server/next";
import { engine } from "@/lib/access";

async function deletePost(req: Request, ctx: { params: { id: string } }) {
  return Response.json({ deleted: true });
}
export const DELETE = withAccess(engine, "delete", "post", deletePost, {
  getUserId: (req) => getSession(req)?.userId,
});

// --- app/layout.tsx (Server Component) ---
import { getPermissions } from "access-engine/server/next";
import { engine } from "@/lib/access";

export default async function Layout({ children }) {
  const userId = await getCurrentUserId();
  const permissions = await getPermissions(engine, userId, [
    { action: "create", resource: "post" },
    { action: "manage", resource: "team" },
    { action: "access", resource: "billing" },
  ]);

  return (
    <AccessProvider permissions={permissions}>
      {children}
    </AccessProvider>
  );
}

// --- middleware.ts ---
import { createNextMiddleware } from "access-engine/server/next";
import { engine } from "@/lib/access";

const checker = createNextMiddleware(engine, {
  getUserId: (req) => getSession(req)?.userId,
  rules: [
    { pattern: /^\/admin/, resource: "admin", action: "access" },
    { pattern: /^\/api\/billing/, resource: "billing" },
  ],
});

export async function middleware(req: NextRequest) {
  const result = await checker(req);
  if (result) return result; // blocked
  return NextResponse.next();
}
*/

// ═══════════════════════════════════════════════
// 9. REACT CLIENT
// ═══════════════════════════════════════════════

/*
// --- lib/access.tsx ---
import React from "react";
import { createAccessControl } from "access-engine/client/react";

export const { AccessProvider, useAccess, Can, Cannot } = createAccessControl(React);

// --- components/Sidebar.tsx ---
"use client";
import { Can, useAccess } from "@/lib/access";

export function Sidebar() {
  const { can } = useAccess();

  return (
    <nav>
      <a href="/dashboard">Dashboard</a>

      <Can action="create" resource="post">
        <a href="/posts/new">New Post</a>
      </Can>

      <Can action="manage" resource="team">
        <a href="/team">Team Settings</a>
      </Can>

      <Can action="access" resource="billing" fallback={<span>Upgrade to access billing</span>}>
        <a href="/billing">Billing</a>
      </Can>

      {can("manage", "user") && (
        <a href="/admin/users">User Management</a>
      )}
    </nav>
  );
}
*/

// ═══════════════════════════════════════════════
// 10. VUE CLIENT
// ═══════════════════════════════════════════════

/*
// --- plugins/access.ts ---
import { ref, computed, inject, provide } from "vue";
import { createVueAccess } from "access-engine/client/vue";

export const { useAccess, createAccessPlugin } = createVueAccess({
  ref, computed, inject, provide,
});

// --- main.ts ---
import { createApp } from "vue";
import { createAccessPlugin } from "./plugins/access";

const app = createApp(App);
app.use(createAccessPlugin(permissionsFromServer));

// --- components/Sidebar.vue ---
<script setup>
import { useAccess } from "@/plugins/access";
const { can } = useAccess();
</script>

<template>
  <nav>
    <a href="/dashboard">Dashboard</a>
    <a v-if="can('create', 'post')" href="/posts/new">New Post</a>
    <a v-if="can('manage', 'team')" href="/team">Team Settings</a>
  </nav>
</template>
*/

// ═══════════════════════════════════════════════
// 11. VANILLA JS (Svelte, Solid, Angular, Web Components)
// ═══════════════════════════════════════════════

/*
import { AccessClient } from "access-engine/client/vanilla";

// From server response
const access = new AccessClient(permissionsFromServer);

// Or fetch from API
const access = await AccessClient.fromServer("/api/my-permissions", {
  headers: { Authorization: `Bearer ${token}` },
});

// Use anywhere
access.can("delete", "post");         // boolean
access.cannot("manage", "billing");   // boolean
access.allowedActions("post");        // ["create", "read", "update", "delete"]
access.hasAnyOn("billing");           // false

// Reactive updates
access.subscribe((perms) => {
  // Re-render your UI
});

// Later, when permissions change
const newPerms = await fetch("/api/my-permissions").then(r => r.json());
access.update(newPerms);
*/

// ═══════════════════════════════════════════════
// 12. RUNTIME ADMIN
// ═══════════════════════════════════════════════

async function runtimeAdmin() {
  const engine = new Engine({ adapter: new MemoryAdapter() })

  // Create roles dynamically
  await engine.admin.saveRole(defineRole('support').name('Support Agent').grantRead('ticket', 'user').grant('update', 'ticket').build())

  // Assign to user
  await engine.admin.assignRole('agent-42', 'support')

  // Set user attributes
  await engine.admin.setAttributes('agent-42', {
    tier: 'senior',
    region: 'EMEA',
  })

  // Add policy at runtime
  await engine.admin.savePolicy(
    policy('escalation-rules')
      .name('Escalation Rules')
      .rule('senior-escalate', (r) =>
        r
          .allow()
          .on('escalate')
          .of('ticket')
          .when((w) => w.attr('tier', 'eq', 'senior')),
      )
      .build(),
  )

  // Test
  console.log(await engine.can('agent-42', 'read', { type: 'ticket', attributes: {} }))
  // true

  console.log(
    await engine.can('agent-42', 'escalate', {
      type: 'ticket',
      attributes: {},
    }),
  )
  // true
}

// ═══════════════════════════════════════════════
// Run
// ═══════════════════════════════════════════════

async function main() {
  console.log('--- Pure RBAC ---')
  await pureRBAC()

  console.log('\n--- Pure ABAC ---')
  await pureABAC()

  console.log('\n--- Hybrid RBAC + ABAC ---')
  await hybrid()

  console.log('\n--- Batch Permissions ---')
  await batchCheck()

  console.log('\n--- Runtime Admin ---')
  await runtimeAdmin()
}

main().catch(console.error)
