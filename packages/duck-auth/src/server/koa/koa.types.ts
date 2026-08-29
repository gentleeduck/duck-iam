export namespace KoaAdapter {
  export type Handler = (ctx: KoaAdapter.Context) => Promise<void>

  /** Koa middleware. Skipping `next()` halts the chain. */
  export type Middleware = (ctx: KoaAdapter.Context, next: () => Promise<void>) => Promise<void>

  export type Context = {
    request: {
      method: string
      url: string
      /** Resolved by the framework against its own proxy trust, never read from a header here. */
      ip?: string
      headers: Record<string, string | string[] | undefined>
      body?: unknown
    }
    params?: Record<string, string>
    status: number
    body: unknown
    set(field: string, value: string | string[]): void
    append?(field: string, value: string | string[]): void
  }
}
