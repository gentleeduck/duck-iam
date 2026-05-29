import { withAuth } from '@gentleduck/auth/client/react/storybook'
import type { Meta, StoryObj } from '@storybook/react'
import { SessionBadge } from './session-badge'

const meta: Meta<typeof SessionBadge> = {
  component: SessionBadge,
  title: 'Auth / SessionBadge',
}
export default meta
type Story = StoryObj<typeof SessionBadge>

export const Guest: Story = { decorators: [withAuth({})] }

export const Authed: Story = {
  decorators: [
    withAuth({
      identity: { id: 'identity-7', profile: { email: 'duck@example.com' } },
      session: { aal: 2, factors: [{ method: 'passkey', completedAt: Date.now() }], id: 'sess-7' },
    }),
  ],
}

export const FormattedIdentity: Story = {
  args: { formatIdentity: (i) => (i.profile as { email?: string })?.email ?? i.id },
  decorators: [
    withAuth({
      identity: { id: 'identity-9', profile: { email: 'duck@example.com' } },
      session: { aal: 2, factors: [{ method: 'passkey', completedAt: Date.now() }], id: 'sess-9' },
    }),
  ],
}

/** Live backend — reflects whatever session the duck-auth-demo server has. */
export const Live: Story = {
  args: { formatIdentity: (i) => (i.profile as { email?: string })?.email ?? i.id },
  decorators: [withAuth({ live: true })],
}
