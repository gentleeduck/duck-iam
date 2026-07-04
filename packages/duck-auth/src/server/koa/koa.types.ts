export namespace KoaAdapter {
  export type Handler = (ctx: KoaAdapter.Context) => Promise<void>

  export type Context = {
    request: {
      method: string
      url: string
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
