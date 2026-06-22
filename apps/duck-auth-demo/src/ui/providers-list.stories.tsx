import { authWithStorybook } from '@gentleduck/auth/client/react/storybook'
import type { Meta, StoryObj } from '@storybook/react'
import { ProvidersList } from './providers-list'

const meta: Meta<typeof ProvidersList> = {
  component: ProvidersList,
  decorators: [authWithStorybook({})],
  title: 'Auth / ProvidersList',
}
export default meta

type Story = StoryObj<typeof ProvidersList>

export const FourProviders: Story = {
  args: {
    providers: [
      { id: 'authGoogle', label: 'Continue with Google' },
      { id: 'authGithub', label: 'Continue with GitHub' },
      { id: 'authMicrosoft', label: 'Continue with Microsoft' },
      { id: 'authApple', label: 'Continue with Apple' },
    ],
  },
}

export const SingleProvider: Story = {
  args: { providers: [{ id: 'authGoogle', label: 'Continue with Google' }] },
}

/** Live backend — clicking magic-link will fire a real begin request. */
export const Live: Story = {
  args: { providers: [{ id: 'magic-link', label: 'Email me a magic link' }] },
  decorators: [authWithStorybook({ live: true })],
}
