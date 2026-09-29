/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { cn } from '@gentleduck/libs/cn'
import { Button } from '@gentleduck/registry-ui/button'
import { useState } from 'react'

/**
 * `<ProvidersList />` — vertical stack of OAuth/SSO provider Buttons, each handing its provider to the caller's
 * `onSelect`. The provider list is config-only (label + id + optional icon), so consumers can plug Google +
 * GitHub + Microsoft + Apple behind one begin route.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function ProvidersList(props: ProvidersList.IProps): React.JSX.Element {
  const { className, onSelect, providers } = props
  const [loading, setLoading] = useState(false)
  return (
    <div className={cn('flex w-full max-w-sm flex-col gap-2', className)}>
      {providers.map((p) => (
        <Button
          disabled={loading}
          key={p.id}
          onClick={async () => {
            setLoading(true)
            try {
              await onSelect(p)
            } finally {
              setLoading(false)
            }
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
    onSelect(provider: IProvider): Promise<void>
  }
}
