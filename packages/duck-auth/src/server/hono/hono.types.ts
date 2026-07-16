export namespace HonoAdapter {
  export type Handler = (ctx: HonoAdapter.Context) => Promise<Response>

  export type Context = {
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

export namespace MountHono {
  /** Subset of Hono's `Context` we use in handlers. */
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
  /** Duck-typed Hono `app` - only `get` / `post` are required. Keeps Hono a peerDep. */
  export type App = {
    get(path: string, handler: (c: HonoCtx) => Response | Promise<Response>): void
    post(path: string, handler: (c: HonoCtx) => Response | Promise<Response>): void
  }

  /** Group identifiers that `opts.skip` understands. */
  export type SkipGroup = 'oauth' | 'magic-link' | 'passkey' | 'totp'

  export type Options = {
    /** Default `'/auth'`. Set to `'/api/auth'` to re-root. */
    prefix?: string
    /** Skip route groups your app doesn't expose. */
    skip?: SkipGroup[]
    /** Reserved for the upcoming `cors: true` shortcut; CORS today is set on the app directly via `hono/cors`. */
    cors?: boolean | { origins: string[] }
  }
}
