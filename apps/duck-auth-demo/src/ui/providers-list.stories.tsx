import { withAuth } from '@gentleduck/auth/client/react/storybook'
import type { Meta, StoryObj } from '@storybook/react'
import { ProvidersList } from './providers-list'

const meta: Meta<typeof ProvidersList> = {
  component: ProvidersList,
  decorators: [withAuth({})],
  title: 'Auth / ProvidersList',
}
export default meta

type Story = StoryObj<typeof ProvidersList>

export const FourProviders: Story = {
  args: {
    providers: [
      { id: 'google', label: 'Continue with Google' },
      { id: 'github', label: 'Continue with GitHub' },
      { id: 'microsoft', label: 'Continue with Microsoft' },
      { id: 'apple', label: 'Continue with Apple' },
    ],
  },
}

export const SingleProvider: Story = {
  args: { providers: [{ id: 'google', label: 'Continue with Google' }] },
}

/** Live backend — clicking magic-link will fire a real begin request. */
export const Live: Story = {
  args: { providers: [{ id: 'magic-link', label: 'Email me a magic link' }] },
  decorators: [withAuth({ live: true })],
}
