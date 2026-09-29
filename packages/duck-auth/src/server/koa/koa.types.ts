/** The Koa context surface the adapter touches. */
export namespace KoaAdapter {
  /** Koa middleware. Skipping `next()` halts the chain. */
  export type Middleware = (ctx: KoaAdapter.Context, next: () => Promise<void>) => Promise<void>

  /** The Koa context fields the adapter reads and writes. */
  export type Context = {
    request: {
      method: string
      /** Resolved by the framework against its own proxy trust, never read from a header here. */
      ip?: string
      headers: Record<string, string | string[] | undefined>
    }
    status: number
    body: unknown
    set(field: string, value: string | string[]): void
    append?(field: string, value: string | string[]): void
  }
}
