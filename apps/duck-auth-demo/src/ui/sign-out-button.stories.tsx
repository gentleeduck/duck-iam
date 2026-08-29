import { authWithStorybook } from '@gentleduck/auth/client/react/storybook'
import type { Meta, StoryObj } from '@storybook/react'
import { SignOutButton } from './sign-out-button'

const meta: Meta<typeof SignOutButton> = {
  component: SignOutButton,
  decorators: [
    authWithStorybook({
      identity: { id: 'identity-1', profile: { email: 'duck@example.com', username: 'duck' } },
      session: { aal: 1, factors: [{ method: 'password', completedAt: new Date() }], id: 'sess-1' },
    }),
  ],
  title: 'Auth / SignOutButton',
}
export default meta

type Story = StoryObj<typeof SignOutButton>
export const Default: Story = {}
export const Destructive: Story = { args: { variant: 'destructive' } }

/** Click to revoke the current backend session. */
export const Live: Story = { decorators: [authWithStorybook({ live: true })] }
