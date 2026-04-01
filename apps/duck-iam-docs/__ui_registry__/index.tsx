import dynamic from 'next/dynamic'

const _ChartBenchmarkIam = dynamic(() => import('~/components/charts/chart-benchmark-iam'), { ssr: false })
const _ChartBenchmarkIamVs = dynamic(() => import('~/components/charts/chart-benchmark-iam-vs'), { ssr: false })
const _ChartBenchmarkIamCompare = dynamic(() => import('~/components/charts/chart-benchmark-iam-compare'), {
  ssr: false,
})

export const Index: Record<string, any> = {
  'chart-benchmark-iam': {
    name: 'chart-benchmark-iam',
    type: 'registry:example',
    registryDependencies: ['chart'],
    files: [{ path: 'charts/chart-benchmark-iam.tsx', type: 'registry:example' }],
    component: _ChartBenchmarkIam,
  },
  'chart-benchmark-iam-vs': {
    name: 'chart-benchmark-iam-vs',
    type: 'registry:example',
    registryDependencies: ['chart'],
    files: [{ path: 'charts/chart-benchmark-iam-vs.tsx', type: 'registry:example' }],
    component: _ChartBenchmarkIamVs,
  },
  'chart-benchmark-iam-compare': {
    name: 'chart-benchmark-iam-compare',
    type: 'registry:example',
    registryDependencies: ['chart'],
    files: [{ path: 'charts/chart-benchmark-iam-compare.tsx', type: 'registry:example' }],
    component: _ChartBenchmarkIamCompare,
  },
}
