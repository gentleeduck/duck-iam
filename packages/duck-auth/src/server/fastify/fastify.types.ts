export namespace FastifyAdapter {
  export type Handler = (
    req: FastifyAdapter.Request,
    reply: FastifyAdapter.Reply,
  ) => Promise<FastifyAdapter.Reply | undefined>

  export type Request = {
    method: string
    url: string
    headers: Record<string, string | string[] | undefined>
    body?: unknown
    params?: Record<string, string>
  }

  export type Reply = {
    status(code: number): FastifyAdapter.Reply
    header(key: string, value: string): FastifyAdapter.Reply
    send(payload: unknown): FastifyAdapter.Reply | undefined | Promise<unknown>
  }
}
