export namespace ElysiaAdapter {
  export type Handler = (ctx: ElysiaAdapter.Context) => Promise<Response>

  export type Context = {
    request: Request
    /** Pre-parsed JSON body (Elysia parses by default when content-type is application/json). */
    body?: unknown
    /** Route params; populated when the route definition declares `:id` etc. */
    params?: Record<string, string>
  }
}
