/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { Button } from '@gentleduck/registry-ui/button'
import { type ComponentProps, useState } from 'react'

/**
 * `<SignOutButton />` — Button that awaits the caller's `onSignOut`. Inherits the registry-ui Button variant
 * API (`variant`, `size`, etc.) by forwarding any ComponentProps<Button>.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function SignOutButton(props: SignOutButton.IProps): React.JSX.Element {
  const { onSignOut, ...buttonProps } = props
  const [loading, setLoading] = useState(false)
  return (
    <Button
      disabled={loading}
      onClick={async () => {
        setLoading(true)
        try {
          await onSignOut()
        } finally {
          setLoading(false)
        }
      }}
      variant="outline"
      {...buttonProps}>
      {loading ? 'Signing out…' : 'Sign out'}
    </Button>
  )
}

/**
 * Namespace merge for SignOutButton.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace SignOutButton {
  export interface IProps extends Omit<ComponentProps<typeof Button>, 'onClick'> {
    onSignOut(): Promise<void>
  }
}
