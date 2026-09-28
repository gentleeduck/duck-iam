import type { ElysiaAdapter } from '@gentleduck/auth/server/elysia'
import type { Server } from 'bun'

export type WithServer = ElysiaAdapter.Context & { server: Server<unknown> | null }

/** Elysia resolves no caller address itself; Bun's server has it. */
export function withIp<C extends WithServer>(ctx: C): C {
  return { ...ctx, ip: ctx.server?.requestIP(ctx.request)?.address }
}
