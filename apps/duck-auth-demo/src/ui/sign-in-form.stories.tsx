import { authWithStorybook } from '@gentleduck/auth/client/react/storybook'
import type { Meta, StoryObj } from '@storybook/react'
import { SignInForm } from './sign-in-form'

const meta: Meta<typeof SignInForm> = {
  component: SignInForm,
  decorators: [authWithStorybook({})],
  title: 'Auth / SignInForm',
}
export default meta
type Story = StoryObj<typeof SignInForm>

export const Default: Story = {}

export const WithDescription: Story = {
  args: {
    description: 'Use the credentials issued by your administrator.',
    title: 'Welcome back',
  },
}

export const AuthedAlready: Story = {
  decorators: [
    authWithStorybook({
      identity: { id: 'identity-1', profile: { email: 'demo@gentleduck.org' } },
      session: { aal: 2, factors: [{ method: 'password', completedAt: Date.now() }], id: 'sess-1' },
    }),
  ],
}

/**
 * Hits the real demo backend at `http://localhost:8787`. Boot it first:
 * `cd apps/duck-auth-demo && bun run db:up && bun run db:migrate && bun run dev`.
 * Then sign up via `POST /auth/signup` (e.g. `alice@test`/`hunter2hunter2`)
 * before driving this story.
 */
export const Live: Story = {
  args: { description: 'Live backend — http://localhost:8787' },
  decorators: [authWithStorybook({ live: true })],
}
