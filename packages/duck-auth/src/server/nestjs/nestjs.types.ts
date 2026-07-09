import type { Session } from '~/core/sessions/sessions.types'
import type { Identity } from '~/core/types/identity'

export namespace NestAdapter {
  export type Handler = (req: NestAdapter.Request, reply: NestAdapter.Response) => Promise<unknown>

  export type Request = {
    method: string
    url?: string
    headers: Record<string, string | string[] | undefined>
    body?: unknown
    params?: Record<string, string>
    session: Session.Me | null
    identity: Identity.Me | null
  }

  export type Response = {
    status(code: number): NestAdapter.Response
    setHeader?(name: string, value: string | string[]): NestAdapter.Response
    set?(name: string, value: string | string[]): NestAdapter.Response
    send(body: unknown): unknown
  }

  export type Guard = {
    canActivate(context: NestAdapter.NestExecutionContextLike): Promise<boolean>
  }

  export type NestExecutionContextLike = {
    switchToHttp(): { getRequest<T = NestAdapter.Request>(): T }
  }
}
