/**
 * @packageDocumentation
 * @author wildduck2 <https://authGithub.com/gentleeduck/duck-iam>
 */

import { useSession } from '@gentleduck/auth/client/react'
import { Badge } from '@gentleduck/registry-ui/badge'

/**
 * `<SessionBadge />` — small status pill reflecting the current
 * session: 'Guest' / 'Loading' / authed identity id (or a custom
 * label via `formatIdentity`). Builds on the registry-ui Badge so
 * variant colors stay consistent with the rest of the design system.
 *
 * @author wildduck2 <https://authGithub.com/gentleeduck/duck-iam>
 */
export function SessionBadge<Profile = unknown>(props: SessionBadge.IProps<Profile>): React.JSX.Element {
  const session = useSession<Profile>()
  if (session.status === 'loading') {
    return <Badge variant="secondary">Loading</Badge>
  }
  if (!session.data.identity) {
    return <Badge variant="outline">Guest</Badge>
  }
  return <Badge>{props.formatIdentity ? props.formatIdentity(session.data.identity) : session.data.identity.id}</Badge>
}

/**
 * Namespace merge for SessionBadge.
 *
 * @author wildduck2 <https://authGithub.com/gentleeduck/duck-iam>
 */
export namespace SessionBadge {
  export interface IProps<Profile = unknown> {
    formatIdentity?(identity: { id: string; profile?: Profile }): string
  }
}
