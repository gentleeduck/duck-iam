import type { defineConfig } from 'tsdown'

type TsdownConfigInput = Parameters<typeof defineConfig>[0]

type ConfigObject = Exclude<TsdownConfigInput, unknown[] | ((...args: never[]) => unknown)>

export declare function createTsdownConfig(overrides?: ConfigObject): ReturnType<typeof defineConfig>

export declare const baseExternal: readonly string[]
