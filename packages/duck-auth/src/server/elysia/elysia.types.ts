/** The Elysia context surface the adapter touches. */
export namespace ElysiaAdapter {
  /** `onBeforeHandle` shape: return a `Response` to short-circuit, `undefined` to continue. */
  export type Middleware = (ctx: ElysiaAdapter.Context) => Promise<Response | undefined>

  /** The Elysia context fields the adapter reads. */
  export type Context = {
    /** Elysia resolves no address itself; an app that knows its proxies sets this. */
    ip?: string
    request: Request
  }
}
