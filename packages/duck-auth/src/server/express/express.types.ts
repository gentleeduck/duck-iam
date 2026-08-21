export namespace ExpressAdapter {
  /** Minimal duck-typed Express request subset. */
  export type Request = {
    method: string
    url: string
    /** Resolved by the framework against its own proxy trust, never read from a header here. */
    ip?: string
    headers: Record<string, string | string[] | undefined>
    body?: unknown
  }

  /** Minimal duck-typed Express response subset. */
  export type Response = {
    status(code: number): Response
    setHeader(name: string, value: string | number | string[]): Response
    append(name: string, value: string): Response
    json(body: unknown): Response
    redirect(status: number, location: string): void
    end(body?: string): void
  }

  /** Express handler signature `(req, res) => Promise<void>`. */
  export type Handler = (req: Request, res: Response) => Promise<void>

  /** Express middleware. Skipping `next()` halts the chain. */
  export type Middleware = (req: Request, res: Response, next: () => void) => Promise<void>
}
