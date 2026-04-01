'use client'

import type { ChartConfig } from '@gentleduck/registry-ui/chart'
import { ChartContainer, ChartTooltip, ChartTooltipContent } from '@gentleduck/registry-ui/chart'
import { Cell, Pie, PieChart } from 'recharts'
import data from '~/public/data/benchmarks/iam.json'

const COLORS = [
  'hsl(142 76% 36%)',
  'hsl(217 91% 60%)',
  'hsl(340 75% 55%)',
  'hsl(45 93% 47%)',
  'hsl(262 83% 58%)',
  'hsl(173 80% 40%)',
  'hsl(24 95% 53%)',
  'hsl(199 89% 48%)',
  'hsl(316 72% 51%)',
  'hsl(60 70% 44%)',
  'hsl(142 50% 50%)',
  'hsl(210 60% 55%)',
  'hsl(0 75% 55%)',
]

const modules = data.moduleSizes
  .filter((m) => m.name !== 'Core (full)')
  .map((m, i) => ({
    name: m.name,
    sizeKB: m.sizeKB,
    fill: COLORS[i % COLORS.length],
  }))

const chartConfig = modules.reduce<Record<string, { label: string; color: string }>>((acc, m, i) => {
  acc[`module${i}`] = { label: m.name as string, color: COLORS[i % COLORS.length] as string }
  return acc
}, {}) satisfies ChartConfig

export function ModuleSizesChart() {
  return (
    <div className="space-y-4">
      <ChartContainer config={chartConfig} className="mx-auto h-[350px] w-full max-w-[500px]">
        <PieChart>
          <ChartTooltip
            content={<ChartTooltipContent formatter={(value, name) => `${name}: ${value} KB`} hideLabel />}
          />
          <Pie
            data={modules}
            dataKey="sizeKB"
            nameKey="name"
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={120}
            paddingAngle={2}>
            {modules.map((entry) => (
              <Cell key={entry.name} fill={entry.fill} />
            ))}
          </Pie>
        </PieChart>
      </ChartContainer>
      <div className="flex flex-wrap justify-center gap-x-4 gap-y-1 text-sm">
        {modules.map((m) => (
          <div key={m.name} className="flex items-center gap-1.5">
            <div className="size-2.5 shrink-0 rounded-sm" style={{ backgroundColor: m.fill }} />
            <span className="text-muted-foreground">
              {m.name} ({m.sizeKB} KB)
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}
