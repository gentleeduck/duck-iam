/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { useSignOut } from '@gentleduck/auth/client/react'
import { Button } from '@gentleduck/registry-ui/button'
import type { ComponentProps } from 'react'

/**
 * `<SignOutButton />` — Button that calls `useSignOut`. Inherits the
 * registry-ui Button variant API (`variant`, `size`, etc.) by
 * forwarding any ComponentProps<Button>.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function SignOutButton(props: SignOutButton.IProps): React.JSX.Element {
  const { onSignedOut, ...buttonProps } = props
  const signOut = useSignOut()
  return (
    <Button
      disabled={signOut.loading}
      onClick={async () => {
        await signOut.mutate()
        onSignedOut?.()
      }}
      variant="outline"
      {...buttonProps}>
      {signOut.loading ? 'Signing out…' : 'Sign out'}
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
    onSignedOut?(): void
  }
}
