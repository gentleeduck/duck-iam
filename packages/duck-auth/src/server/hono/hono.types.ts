/** The Hono context surface the handlers touch. */
export namespace HonoAdapter {
  /** A route handler. */
  export type Handler = (ctx: HonoAdapter.Context) => Promise<Response>

  /** Hono middleware. Returning a `Response` short-circuits the chain. */
  export type Middleware = (ctx: HonoAdapter.Context, next: () => Promise<void>) => Promise<Response | undefined>

  /** The Hono context fields the adapter reads. */
  export type Context = {
    /** Hono resolves no address itself; an app that knows its proxies sets this. */
    ip?: string
    req: {
      method: string
      url: string
      header(name?: string): string | undefined | Record<string, string>
      raw: Request
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
      param: (n: string) => string | undefined
      header: (n?: string) => unknown
    }
  }
  /** Duck-typed Hono `app`: only `get` and `post` are required, so Hono is not a dependency of this
   *  package at all. There is no `use`, so no middleware can be mounted through this type. */
  export type App<C extends HonoCtx = HonoCtx> = {
    get(path: string, handler: (c: C) => Response | Promise<Response>): void
    post(path: string, handler: (c: C) => Response | Promise<Response>): void
  }

  /** Group identifiers that `opts.skip` understands. `'totp'` gates every MFA route, backup-code
   *  regeneration included, so there is no way to skip one without the other. */
  export type SkipGroup = 'oauth' | 'magic-link' | 'passkey' | 'totp'

  /** Where `mountHono` mounts, what it skips, and how it reads the caller. */
  export type Options<C extends HonoCtx = HonoCtx> = {
    /** Default `'/auth'`. Set to `'/api/auth'` to re-root. */
    prefix?: string
    /** Skip route groups your app doesn't expose. */
    skip?: SkipGroup[]
    /** The caller's address, which Hono does not resolve, for the session row and the hijack and anomaly
     *  checks: `mountHono<Context>(app, auth, { ip: (c) => getConnInfo(c).remote.address })`. */
    ip?: (c: C) => string | undefined
  }
}
