/** The Hono context surface the handlers touch. */
export namespace HonoAdapter {
  export type Handler = (ctx: HonoAdapter.Context) => Promise<Response>

  /** Hono middleware. Returning a `Response` short-circuits the chain. */
  export type Middleware = (ctx: HonoAdapter.Context, next: () => Promise<void>) => Promise<Response | undefined>

  export type Context = {
    /** Hono resolves no address itself; an app that knows its proxies sets this. */
    ip?: string
    req: {
      method: string
      url: string
      header(name?: string): string | undefined | Record<string, string>
      raw: Request
      json: () => Promise<unknown>
      param(name: string): string | undefined
    }
  }
}

/** Options for `mountHono`, which mounts every route on one app. */
export namespace MountHono {
  /** The subset of Hono's `Context` the handlers touch. */
  export type HonoCtx = {
    req: {
      method: string
      url: string
      raw: Request
      json: () => Promise<unknown>
      param: (n: string) => string | undefined
      header: (n?: string) => unknown
    }
  }
  /** Duck-typed Hono `app`: only `get` and `post` are required, so Hono is not a dependency of this
   *  package at all. There is no `use`, so no middleware can be mounted through this type. */
  export type App = {
    get(path: string, handler: (c: HonoCtx) => Response | Promise<Response>): void
    post(path: string, handler: (c: HonoCtx) => Response | Promise<Response>): void
  }

  /** Group identifiers that `opts.skip` understands. `'totp'` gates every MFA route, backup-code
   *  regeneration included, so there is no way to skip one without the other. */
  export type SkipGroup = 'oauth' | 'magic-link' | 'passkey' | 'totp'

  export type Options = {
    /** Default `'/auth'`. Set to `'/api/auth'` to re-root. */
    prefix?: string
    /** Skip route groups your app doesn't expose. */
    skip?: SkipGroup[]
    /** WARN: inert. Nothing reads this, and `App` exposes no `use` to mount middleware through, so a
     *  value here is silently ignored. Mount `hono/cors` on the app yourself. */
    cors?: boolean | { origins: string[] }
  }
}
