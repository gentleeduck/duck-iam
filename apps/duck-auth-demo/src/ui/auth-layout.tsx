/**
 * @packageDocumentation
 * @author wildduck2 <https://authGithub.com/gentleeduck/duck-iam>
 */

import { cn } from '@gentleduck/libs/cn'
import type { ReactNode } from 'react'

/**
 * `<AuthLayout />` — page-level wrapper that vertically centers the
 * auth surface on a muted background. Stack any of the duck-auth UI
 * components inside (e.g. `<SignInForm />` + `<ProvidersList />`).
 *
 * @author wildduck2 <https://authGithub.com/gentleeduck/duck-iam>
 */
export function AuthLayout(props: AuthLayout.IProps): React.JSX.Element {
  return (
    <div
      className={cn(
        'flex min-h-[600px] w-full flex-col items-center justify-center gap-6 bg-muted/30 p-6',
        props.className,
      )}>
      {props.brand ? <div className="text-center">{props.brand}</div> : null}
      <div className="flex w-full max-w-sm flex-col gap-4">{props.children}</div>
      {props.footer ? <div className="text-muted-foreground text-sm">{props.footer}</div> : null}
    </div>
  )
}

/**
 * Namespace merge for AuthLayout.
 *
 * @author wildduck2 <https://authGithub.com/gentleeduck/duck-iam>
 */
export namespace AuthLayout {
  export interface IProps {
    children: ReactNode
    brand?: ReactNode
    footer?: ReactNode
    className?: string
  }
}
