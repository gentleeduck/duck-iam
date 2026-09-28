/** Every backend example and its port. Each client's dev server proxies `/api/<name>` to one. */
export const BACKENDS = {
  express: 4100,
  hono: 4200,
  fastify: 4300,
  koa: 4400,
  elysia: 4500,
  nest: 4600,
  bun: 4700,
} as const

export type Backend = keyof typeof BACKENDS

/** The dev-server proxy table, one entry per backend, with the `/api/<name>` prefix stripped. */
export const proxy = Object.fromEntries(
  Object.entries(BACKENDS).map(([name, port]) => [
    `/api/${name}`,
    { target: `http://localhost:${port}`, rewrite: (path: string) => path.slice(`/api/${name}`.length) },
  ]),
)
