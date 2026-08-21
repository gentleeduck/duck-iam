export namespace ElysiaAdapter {
  export type Handler = (ctx: ElysiaAdapter.Context) => Promise<Response>

  /** `onBeforeHandle` shape: return a `Response` to short-circuit, `undefined` to continue. */
  export type Middleware = (ctx: ElysiaAdapter.Context) => Promise<Response | undefined>

  export type Context = {
    /** Elysia resolves no address itself; an app that knows its proxies sets this. */
    ip?: string
    request: Request
    /** Pre-parsed JSON body (Elysia parses by default when content-type is application/json). */
    body?: unknown
    /** Route params; populated when the route definition declares `:id` etc. */
    params?: Record<string, string>
  }
}
