/** The Fastify request and reply surface the adapter touches. */
export namespace FastifyAdapter {
  /** `preHandler` hook shape. Sending is not what halts the chain - awaiting the reply is, so a hook that
   *  refuses a request must `await` the send before it returns. */
  export type PreHandler = (req: FastifyAdapter.Request, reply: FastifyAdapter.Reply) => Promise<void>

  /** The Fastify request fields the adapter reads. */
  export type Request = {
    method: string
    /** Resolved by the framework against its own proxy trust, never read from a header here. */
    ip?: string
    headers: Record<string, string | string[] | undefined>
  }

  /** The Fastify reply methods the adapter calls. */
  export type Reply = {
    status(code: number): FastifyAdapter.Reply
    header(key: string, value: string): FastifyAdapter.Reply
    send(payload: unknown): FastifyAdapter.Reply | undefined | Promise<unknown>
  }
}
