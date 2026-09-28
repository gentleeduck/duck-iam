/** Framework doubles typed against each adapter's own surface, for the tests driving several adapters. */
import type { ExpressAdapter } from '~/server/express'
import type { FastifyAdapter } from '~/server/fastify'
import type { HonoAdapter } from '~/server/hono'
import type { KoaAdapter } from '~/server/koa'
import type { NestAdapter } from '~/server/nestjs'

/** An Express response nothing writes to. */
export const expressRes: ExpressAdapter.Response = {
  append: () => expressRes,
  end: () => {},
  json: () => expressRes,
  redirect: () => {},
  setHeader: () => expressRes,
  status: () => expressRes,
}

/** A Fastify reply nothing writes to. */
export const fastifyReply: FastifyAdapter.Reply = {
  header: () => fastifyReply,
  send: () => fastifyReply,
  status: () => fastifyReply,
}

/** A Koa context around `request`. */
export function koaCtx(request: KoaAdapter.Context['request']): KoaAdapter.Context {
  return { body: undefined, request, set: () => {}, status: 404 }
}

/** A Nest execution context around `req`. */
export function nestCtx(req: NestAdapter.Request): NestAdapter.NestExecutionContextLike {
  return { switchToHttp: () => ({ getRequest: () => req }) }
}

/** A Hono context around `raw`, its `header` reading `raw` as Hono's does. */
export function honoCtx(raw: Request, ip?: string): HonoAdapter.Context {
  return {
    ...(ip && { ip }),
    req: {
      header: (name) => (name === undefined ? Object.fromEntries(raw.headers) : (raw.headers.get(name) ?? undefined)),
      method: raw.method,
      param: () => undefined,
      raw,
      url: raw.url,
    },
  }
}

/** A 1 MiB request body in 16 KiB pieces, pulled only when read: how many pieces the reader took, and
 *  whether it cancelled the rest. */
export function streamedMiB(): { body: ReadableStream<Uint8Array>; cancelled: () => boolean; pulled: () => number } {
  const piece = new Uint8Array(16 * 1024).fill(0x20)
  let pulled = 0
  let cancelled = false
  const body = new ReadableStream<Uint8Array>(
    {
      cancel: () => {
        cancelled = true
      },
      pull: (c) => {
        if (pulled === 64) return c.close()
        pulled++
        c.enqueue(piece)
      },
    },
    { highWaterMark: 0 },
  )
  return { body, cancelled: () => cancelled, pulled: () => pulled }
}

/** A POST carrying `body`; a stream needs `duplex`, which the DOM's `RequestInit` does not declare. */
export function postRequest(url: string, body: BodyInit, headers?: HeadersInit): Request {
  const init: RequestInit & { duplex: 'half' } = { body, duplex: 'half', headers: headers ?? {}, method: 'POST' }
  return new Request(url, init)
}
