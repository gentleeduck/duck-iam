import type { Meta, StoryObj } from '@storybook/react'
import { live } from './live'
import { SignOutButton } from './sign-out-button'

const meta: Meta<typeof SignOutButton> = {
  args: { onSignOut: () => new Promise((r) => setTimeout(r, 500)) },
  component: SignOutButton,
  title: 'Auth / SignOutButton',
}
export default meta

type Story = StoryObj<typeof SignOutButton>
export const Default: Story = {}
export const Destructive: Story = { args: { variant: 'destructive' } }

/** Click to revoke the current backend session. */
export const Live: Story = { args: { onSignOut: live.signOut } }
