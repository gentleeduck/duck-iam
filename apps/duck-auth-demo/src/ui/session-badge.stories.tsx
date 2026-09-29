import type { Meta, StoryObj } from '@storybook/react'
import { useEffect, useState } from 'react'
import { live } from './live'
import { SessionBadge } from './session-badge'

const meta: Meta<typeof SessionBadge> = {
  component: SessionBadge,
  title: 'Auth / SessionBadge',
}
export default meta
type Story = StoryObj<typeof SessionBadge>

export const Loading: Story = { args: { label: null, loading: true } }

export const Guest: Story = { args: { label: null } }

export const Authed: Story = { args: { label: 'duck@example.com' } }

/** Live backend — reflects whatever session the duck-auth-demo server has. */
export const Live: Story = {
  render: function LiveBadge() {
    const [label, setLabel] = useState<string | null | undefined>(undefined)
    useEffect(() => {
      live.session().then(setLabel)
    }, [])
    return <SessionBadge label={label ?? null} loading={label === undefined} />
  },
}
