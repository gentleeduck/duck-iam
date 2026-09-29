import type { Meta, StoryObj } from '@storybook/react'
import { live } from './live'
import { ProvidersList } from './providers-list'

const meta: Meta<typeof ProvidersList> = {
  args: { onSelect: () => new Promise((r) => setTimeout(r, 500)) },
  component: ProvidersList,
  title: 'Auth / ProvidersList',
}
export default meta

type Story = StoryObj<typeof ProvidersList>

export const FourProviders: Story = {
  args: {
    providers: [
      { id: 'oauth:google', label: 'Continue with Google' },
      { id: 'oauth:github', label: 'Continue with GitHub' },
      { id: 'oauth:microsoft', label: 'Continue with Microsoft' },
      { id: 'oauth:apple', label: 'Continue with Apple' },
    ],
  },
}

export const SingleProvider: Story = {
  args: { providers: [{ id: 'oauth:google', label: 'Continue with Google' }] },
}

/** Live backend — clicking magic-link will fire a real begin request. */
export const Live: Story = {
  args: {
    onSelect: live.begin,
    providers: [{ id: 'magic-link', input: { email: 'alice@test' }, label: 'Email me a magic link' }],
  },
}
