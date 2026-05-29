/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { useBeginProvider } from '@gentleduck/auth/client/react'
import { cn } from '@gentleduck/libs/cn'
import { Button } from '@gentleduck/registry-ui/button'

/**
 * `<ProvidersList />` — vertical stack of OAuth/SSO provider Buttons,
 * each wired to `useBeginProvider`. The provider list is config-only
 * (label + id + optional icon), so consumers can plug Google +
 * GitHub + Microsoft + Apple without writing duplicate handlers.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function ProvidersList(props: ProvidersList.IProps): React.JSX.Element {
  const { className, providers } = props
  const begin = useBeginProvider()
  return (
    <div className={cn('flex w-full max-w-sm flex-col gap-2', className)}>
      {providers.map((p) => (
        <Button
          disabled={begin.loading}
          key={p.id}
          onClick={async () => {
            const { body } = await begin.mutate({ id: p.id, input: p.input })
            const url = (body as { authorizationUrl?: string } | null)?.authorizationUrl
            if (url) globalThis.location?.assign(url)
          }}
          variant="outline">
          {p.icon ? <span aria-hidden>{p.icon}</span> : null}
          {p.label}
        </Button>
      ))}
    </div>
  )
}

/**
 * Namespace merge for ProvidersList.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace ProvidersList {
  export interface IProvider {
    id: string
    label: string
    icon?: React.ReactNode
    input?: unknown
  }
  export interface IProps {
    className?: string
    providers: IProvider[]
  }
}
