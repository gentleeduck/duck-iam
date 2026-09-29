/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { Badge } from '@gentleduck/registry-ui/badge'

/**
 * `<SessionBadge />` — small status pill reflecting the current session: 'Loading', 'Guest', or the signed-in
 * caller's label. Builds on the registry-ui Badge so variant colors stay consistent with the rest of the
 * design system.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function SessionBadge(props: SessionBadge.IProps): React.JSX.Element {
  if (props.loading) return <Badge variant="secondary">Loading</Badge>
  if (props.label === null) return <Badge variant="outline">Guest</Badge>
  return <Badge>{props.label}</Badge>
}

/**
 * Namespace merge for SessionBadge.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace SessionBadge {
  export interface IProps {
    /** The signed-in caller as the app names them, or `null` for a guest. */
    label: string | null
    loading?: boolean
  }
}
