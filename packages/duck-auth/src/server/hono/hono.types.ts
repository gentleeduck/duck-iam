/** The Hono context surface the adapter touches. */
export namespace HonoAdapter {
  /** Hono middleware. Returning a `Response` short-circuits the chain. */
  export type Middleware = (ctx: HonoAdapter.Context, next: () => Promise<void>) => Promise<Response | undefined>

  /** The Hono context fields the adapter reads. */
  export type Context = {
    /** Hono resolves no address itself; an app that knows its proxies sets this. */
    ip?: string
    req: {
      header(name?: string): string | undefined | Record<string, string>
      raw: Request
    }
  }

  /** The subset of Hono's own `Context` that `toHonoAdapterCtx` reads. */
  export type HonoCtx = {
    req: {
      raw: Request
      header: (n?: string) => unknown
    }
  }
}
