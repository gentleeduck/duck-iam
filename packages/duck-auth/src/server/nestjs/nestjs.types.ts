import type { Identities } from '~/core/identities/identities.types'
import type { Sessions } from '~/core/sessions/sessions.types'

export namespace NestAdapter {
  export type Handler = (req: NestAdapter.Request, reply: NestAdapter.Response) => Promise<unknown>

  export type Request = {
    method: string
    url?: string
    headers: Record<string, string | string[] | undefined>
    body?: unknown
    params?: Record<string, string>
    session: Sessions.Me | null
    identity: Identities.Me | null
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
