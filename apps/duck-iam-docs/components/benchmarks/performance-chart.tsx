'use client'

import type { ChartConfig } from '@gentleduck/registry-ui/chart'
import { ChartContainer, ChartTooltip, ChartTooltipContent } from '@gentleduck/registry-ui/chart'
import { Bar, BarChart, CartesianGrid, Cell, XAxis, YAxis } from 'recharts'

const GREEN = 'hsl(142 76% 36%)'
const BLUE = 'hsl(217 91% 60%)'
const GRAY = 'hsl(215 16% 47%)'

// --- Performance Bar Chart ---

const perfData = [
  { name: '@casl/ability', opsPerSec: 15_420_000, type: 'casl' },
  { name: '@gentleduck/iam [PROD]', opsPerSec: 8_060_000, type: 'duck' },
  { name: 'easy-rbac', opsPerSec: 4_050_000, type: 'other' },
  { name: '@rbac/rbac', opsPerSec: 2_490_000, type: 'other' },
  { name: '@gentleduck/iam [DEV]', opsPerSec: 1_180_000, type: 'duck' },
  { name: 'accesscontrol', opsPerSec: 600_000, type: 'other' },
  { name: 'casbin', opsPerSec: 118_000, type: 'other' },
]

function getBarColor(type: string) {
  if (type === 'duck') return GREEN
  if (type === 'casl') return BLUE
  return GRAY
}

const perfConfig = {
  opsPerSec: { label: 'ops/sec' },
} satisfies ChartConfig

export function PerformanceBarChart() {
  return (
    <ChartContainer config={perfConfig} className="h-[350px] w-full">
      <BarChart data={perfData} layout="vertical" margin={{ left: 0, right: 40 }}>
        <CartesianGrid horizontal={false} strokeDasharray="3 3" />
        <XAxis type="number" tickFormatter={(v: number) => `${(v / 1_000_000).toFixed(0)}M`} />
        <YAxis type="category" dataKey="name" width={180} tick={{ fontSize: 12 }} />
        <ChartTooltip
          content={<ChartTooltipContent formatter={(value) => `${Number(value).toLocaleString()} ops/sec`} />}
        />
        <Bar dataKey="opsPerSec" radius={[0, 4, 4, 0]}>
          {perfData.map((entry) => (
            <Cell key={entry.name} fill={getBarColor(entry.type)} />
          ))}
        </Bar>
      </BarChart>
    </ChartContainer>
  )
}

// --- Bundle Size Chart ---

const bundleData = [
  { name: 'easy-rbac', sizeKB: 2, type: 'other' },
  { name: '@rbac/rbac', sizeKB: 4, type: 'other' },
  { name: '@casl/ability', sizeKB: 6, type: 'other' },
  { name: 'accesscontrol', sizeKB: 8.2, type: 'other' },
  { name: 'role-acl', sizeKB: 12, type: 'other' },
  { name: '@gentleduck/iam', sizeKB: 21, type: 'duck' },
  { name: 'casbin', sizeKB: 30, type: 'other' },
]

const bundleConfig = {
  sizeKB: { label: 'Size (gzip KB)' },
} satisfies ChartConfig

export function BundleSizeChart() {
  return (
    <ChartContainer config={bundleConfig} className="h-[320px] w-full">
      <BarChart data={bundleData} layout="vertical" margin={{ left: 0, right: 40 }}>
        <CartesianGrid horizontal={false} strokeDasharray="3 3" />
        <XAxis type="number" tickFormatter={(v: number) => `${v} KB`} />
        <YAxis type="category" dataKey="name" width={160} tick={{ fontSize: 12 }} />
        <ChartTooltip content={<ChartTooltipContent formatter={(value) => `${value} KB (gzipped)`} />} />
        <Bar dataKey="sizeKB" radius={[0, 4, 4, 0]}>
          {bundleData.map((entry) => (
            <Cell key={entry.name} fill={entry.type === 'duck' ? GREEN : GRAY} />
          ))}
        </Bar>
      </BarChart>
    </ChartContainer>
  )
}
