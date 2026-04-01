'use client'

import type { ChartConfig } from '@gentleduck/registry-ui/chart'
import { ChartContainer, ChartTooltip, ChartTooltipContent } from '@gentleduck/registry-ui/chart'
import { Bar, BarChart, CartesianGrid, Cell, XAxis, YAxis } from 'recharts'
import data from '~/public/data/benchmarks/iam.json'

const CORE_COLOR = 'hsl(142 76% 36%)'
const ENGINE_COLOR = 'hsl(217 91% 60%)'

const chartData = [
  ...data.corePerformance.map((d) => ({ name: d.label, us: d.us, type: 'core' as const })),
  ...data.enginePerformance.map((d) => ({ name: d.label, us: d.us, type: 'engine' as const })),
]

const chartConfig = {
  core: { label: 'Core evaluation', color: CORE_COLOR },
  engine: { label: 'Engine (with LRU cache)', color: ENGINE_COLOR },
} satisfies ChartConfig

export function InternalPerfChart() {
  return (
    <ChartContainer config={chartConfig} className="h-[420px] w-full">
      <BarChart data={chartData} layout="vertical" margin={{ left: 0, right: 40 }}>
        <CartesianGrid horizontal={false} strokeDasharray="3 3" />
        <XAxis type="number" tickFormatter={(v: number) => `${v} us`} />
        <YAxis type="category" dataKey="name" width={250} tick={{ fontSize: 11 }} />
        <ChartTooltip content={<ChartTooltipContent formatter={(value) => `${value} us`} />} />
        <Bar dataKey="us" radius={[0, 4, 4, 0]}>
          {chartData.map((entry) => (
            <Cell key={entry.name} fill={entry.type === 'core' ? CORE_COLOR : ENGINE_COLOR} />
          ))}
        </Bar>
      </BarChart>
    </ChartContainer>
  )
}
