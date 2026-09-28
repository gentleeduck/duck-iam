import type { Middleware, Req } from '@gentleduck/iam/server/express'
import type { Request, RequestHandler } from 'express'

// Express 5's route params are `string | string[]`; duck-iam's `Req.params` wants plain strings.
function stringParams(params: Request['params']): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [key, value] of Object.entries(params)) {
    if (typeof value === 'string') out[key] = value
  }
  return out
}

export function asHandler(mw: Middleware): RequestHandler {
  return (req, res, next) => {
    const shimmed: Req = {
      method: req.method,
      path: req.path,
      url: req.url,
      ip: req.ip,
      params: stringParams(req.params),
      headers: req.headers,
      body: req.body,
      session: req.session,
    }
    mw(shimmed, res, next)
  }
}

/** Reads a route param as a plain string, narrowing away Express 5's `string | string[]`. */
export function paramId(req: { params: Request['params'] }, name = 'id'): string {
  const value = req.params[name]
  if (typeof value !== 'string') throw new Error(`missing path param: ${name}`)
  return value
}
