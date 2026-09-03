import { describe, expect, it } from 'vitest'
import { IamFile, IamFileAdapter } from '../index'

/**
 * `getSubjectAttributes` throws on a corrupt row because "corruption != empty;
 * `{}` would silently strip ABAC" - redis and http re-derive that from the
 * stored bytes on every read, so they keep throwing forever.
 *
 * The file adapter's marker lived in `_cache` only. The next `_flushNow`
 * serialised the whole cache: the `Set` stringified to `{}`, and the corrupt row
 * had already been dropped from `attributes`, so the flush wrote a store in
 * which the row simply did not exist - quietly repairing it into the "empty"
 * state the read had just refused to serve. An ABAC deny resting on that
 * subject's attributes failed closed on the first process and open on the next,
 * triggered by nothing but an unrelated write and a restart.
 */
function makeFs(initial: string): { fs: IamFile.IFS; read: () => string } {
  const files = new Map<string, string>([['/store.json', initial]])
  return {
    fs: {
      async mkdir() {},
      async readFile(p: string) {
        const v = files.get(p)
        if (v === undefined) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
        return v
      },
      async writeFile(p: string, d: string) {
        files.set(p, d)
      },
    },
    read: () => files.get('/store.json') ?? '',
  }
}

const CORRUPT = JSON.stringify({
  assignments: { 'someone-else': [{ role: 'viewer' }] },
  attributes: { bad: 'not-an-object', good: { tier: 'gold' } },
  policies: {},
  // `assignRole` refuses a role that is not stored, and the unrelated write
  // below has to be a write that succeeds.
  roles: { editor: { id: 'editor', name: 'Editor', permissions: [] } },
})

function adapterOn(fs: IamFile.IFS) {
  return new IamFileAdapter({ fs, onPolicyError: () => {}, path: '/store.json', rootDir: '/' })
}

describe('file adapter: a corrupt attributes row survives a flush', () => {
  it('still throws after an unrelated write and a fresh load', async () => {
    const { fs, read } = makeFs(CORRUPT)

    const first = adapterOn(fs)
    await expect(first.getSubjectAttributes('bad')).rejects.toThrow(/corrupted attributes/)

    // An unrelated write is all it took: this is the flush that used to erase it.
    await first.assignRole('someone-else', 'editor')

    const second = adapterOn(fs)
    await expect(second.getSubjectAttributes('bad')).rejects.toThrow(/corrupted attributes/)

    // The raw value goes back out verbatim, and the marker never reaches disk.
    const onDisk = JSON.parse(read())
    expect(onDisk.attributes.bad).toBe('not-an-object')
    expect(Object.hasOwn(onDisk, 'corruptAttributes')).toBe(false)
  })

  it('keeps the unrelated rows and the unrelated write', async () => {
    const { fs, read } = makeFs(CORRUPT)
    const adapter = adapterOn(fs)

    expect(await adapter.getSubjectAttributes('good')).toEqual({ tier: 'gold' })
    await adapter.assignRole('someone-else', 'editor')

    const onDisk = JSON.parse(read())
    expect(onDisk.attributes.good).toEqual({ tier: 'gold' })
    expect(onDisk.assignments['someone-else']).toEqual([{ role: 'viewer' }, { role: 'editor' }])
  })

  // An admin write is the sanctioned repair: it clears the marker, and the row
  // must then read back normally in this process and the next.
  it('an admin write repairs the row for good', async () => {
    const { fs } = makeFs(CORRUPT)
    const first = adapterOn(fs)

    await first.setSubjectAttributes('bad', { tier: 'silver' })
    expect(await first.getSubjectAttributes('bad')).toEqual({ tier: 'silver' })

    const second = adapterOn(fs)
    expect(await second.getSubjectAttributes('bad')).toEqual({ tier: 'silver' })
  })
})
