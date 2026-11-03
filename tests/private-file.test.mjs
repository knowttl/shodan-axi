import assert from 'node:assert/strict'
import fs, { mkdtemp, readFile, readdir, rm } from 'node:fs/promises'
import { syncBuiltinESMExports } from 'node:module'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { readPrivate, writePrivate } from '../dist/private-file.js'

for (const signal of ['SIGINT', 'SIGTERM']) {
  test(`Windows update interrupted by ${signal} during rename backoff preserves the configuration`, async t => {
    const root = await mkdtemp(join(tmpdir(), 'shodan-acl-'))
    const target = join(root, 'config.json')
    try {
      await writePrivate(target, 'original')
      t.mock.method(fs, 'rename', async () => {
        throw Object.assign(new Error('Sharing violation'), { code: 'EBUSY' })
      }, { times: 1 })
      syncBuiltinESMExports()
      t.mock.method(globalThis, 'setTimeout', callback => {
        process.emit(signal)
        callback()
      })
      await assert.rejects(writePrivate(target, 'replacement', { platform: 'win32', acl: () => {} }), { code: 'INTERRUPTED' })
      assert.equal(await readFile(target, 'utf8'), 'original')
      assert.deepEqual(await readdir(root), ['config.json'])
    } finally {
      t.mock.restoreAll()
      syncBuiltinESMExports()
      await rm(root, { recursive: true, force: true })
    }
  })
}

test('Windows ACL boundary protects writes and verifies reads', async () => {
  const root = await mkdtemp(join(tmpdir(), 'shodan-acl-'))
  const target = join(root, 'config.json')
  const actions = []
  const options = { platform: 'win32', acl: (path, action, directory) => { actions.push({ path, action, directory }) } }
  try {
    await writePrivate(target, 'value', options)
    assert.equal(await readFile(target, 'utf8'), 'value')
    assert.equal(await readPrivate(target, false, options), 'value')
    assert.equal(actions[0].action, 'restrict')
    assert.equal(actions[0].directory, true)
    assert.equal(actions[1].action, 'restrict')
    assert.equal(actions[1].directory, false)
    assert.deepEqual(actions.at(-1), { path: target, action: 'verify', directory: false })
  } finally { await rm(root, { recursive: true, force: true }) }
})

for (const secret of [false, true]) {
  test(`Windows rejects an unprotected ${secret ? 'secret' : 'configuration'} read`, async () => {
    const root = await mkdtemp(join(tmpdir(), 'shodan-acl-'))
    const target = join(root, 'private')
    try {
      await writePrivate(target, 'value')
      const options = { platform: 'win32', acl: (_path, action) => {
        if (action === 'verify') throw new Error('Unprotected ACL')
      } }
      await assert.rejects(readPrivate(target, secret, options), { code: 'CONFIG_INSECURE' })
    } finally { await rm(root, { recursive: true, force: true }) }
  })
}

test('Windows refuses to overwrite an unprotected configuration', async () => {
  const root = await mkdtemp(join(tmpdir(), 'shodan-acl-'))
  const target = join(root, 'config.json')
  try {
    await writePrivate(target, 'original')
    const options = { platform: 'win32', acl: (_path, action) => {
      if (action === 'verify') throw new Error('Unprotected ACL')
    } }
    await assert.rejects(writePrivate(target, 'replacement', options), { code: 'CONFIG_INSECURE' })
    assert.equal(await readFile(target, 'utf8'), 'original')
  } finally { await rm(root, { recursive: true, force: true }) }
})
