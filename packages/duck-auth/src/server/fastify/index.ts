/** Fastify adapter: the CSRF guard, the actor wrapper and the caller fingerprint for your own routes. A route
 *  answers a flow's intents with `reply.send(executeIntents(intents))`. */

import { withRequestActor } from '~/core/actor'
import type { Csrf } from '~/core/csrf'
import { csrfGuard } from '~/core/csrf'
import type { AuthEngine } from '~/core/engine'
import {
  type ActorOptions,
  type CallerFingerprint,
  callerContext,
  errorToHttp,
  nodeHeadersToFetch,
  requestSecurity,
} from '../generic'

import type { FastifyAdapter } from './fastify.types'

/** Convert the loose Fastify header bag into a Web Fetch Headers object. */
const toFetchHeaders: (headers: FastifyAdapter.Request['headers']) => Headers = nodeHeadersToFetch

function handleError(err: unknown, reply: FastifyAdapter.Reply): FastifyAdapter.Reply {
  const { status, body } = errorToHttp(err)
  reply.status(status)
  reply.header('cache-control', 'no-store')
  reply.header('content-type', 'application/json; charset=utf-8')
  reply.send(JSON.stringify(body))
  return reply
}

/** The fingerprint Fastify resolved, for `flows.signIn` to stamp onto the session. */
export function fastifyCaller(req: FastifyAdapter.Request): CallerFingerprint {
  return callerContext({ ip: req.ip, userAgent: req.headers['user-agent'] })
}

/** {@link ActorOptions} over Fastify's request. */
export type FastifyActorOptions<Req extends FastifyAdapter.Request = FastifyAdapter.Request> = ActorOptions<Req>

/** Wrap one handler so its writes carry the request's actor; per-handler, since Fastify composes no
 *  `next`. A handler annotated with Fastify's own request and reply types keeps them. See
 *  `core/actor/README.md` for what runs unbound and what raises. */
export function fastifyWithActor<Req extends FastifyAdapter.Request, Reply extends FastifyAdapter.Reply, Out>(
  auth: AuthEngine,
  handler: (req: Req, reply: Reply) => Promise<Out>,
  opts: FastifyActorOptions<Req> = {},
): (req: Req, reply: Reply) => Promise<Out> {
  return (req, reply) =>
    withRequestActor(
      auth,
      { headers: toFetchHeaders(req.headers) },
      () => handler(req, reply),
      requestSecurity(auth, { caller: opts.getCaller?.(req), onAnomaly: opts.onAnomaly, onHijack: opts.onHijack }),
    )
}

/** CSRF guard for your own routes: `fastify.addHook('preHandler', fastifyCsrf(auth))`. */
export function fastifyCsrf(auth: AuthEngine, opts: Csrf.GuardOptions = {}): FastifyAdapter.PreHandler {
  return async (req, reply) => {
    try {
      await csrfGuard(auth, { headers: toFetchHeaders(req.headers), method: req.method }, opts)
    } catch (err) {
      // SECURITY: `await`: Fastify's Reply is thenable, and only awaiting it stops the handler running after
      // the 403.
      await handleError(err, reply)
    }
  }
}

export type { FastifyAdapter } from './fastify.types'
