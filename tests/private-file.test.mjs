import assert from 'node:assert/strict'
import fs, { chmod, lstat, mkdtemp, readFile, readdir, rm } from 'node:fs/promises'
import { syncBuiltinESMExports } from 'node:module'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { appendPrivate, readPrivate, writePrivate } from '../dist/private-file.js'

test('journal appends preserve existing contents beyond the secret-file size limit', async () => {
  const root = await mkdtemp(join(tmpdir(), 'shodan-journal-'))
  const path = join(root, 'writes.log')
  const original = 'x'.repeat(1024 * 1024 + 1)
  try {
    await appendPrivate(path, original)
    await appendPrivate(path, '\nintent\n')
    await appendPrivate(path, 'result\n')
    assert.equal(await readFile(path, 'utf8'), `${original}\nintent\nresult\n`)
  } finally { await rm(root, { recursive: true, force: true }) }
})

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
  const created = join(root, 'private')
  const directory = join(created, 'nested')
  const target = join(directory, 'config.json')
  const actions = []
  const options = { platform: 'win32', acl: (path, action, directory) => { actions.push({ path, action, directory }) } }
  try {
    await writePrivate(target, 'value', options)
    assert.equal(await readFile(target, 'utf8'), 'value')
    assert.equal(await readPrivate(target, false, options), 'value')
    assert.deepEqual(actions.filter(item => item.directory), [
      { path: directory, action: 'restrict', directory: true },
      { path: created, action: 'restrict', directory: true },
    ])
    assert.equal(actions[2].action, 'restrict')
    assert.equal(actions[2].directory, false)
    assert.deepEqual(actions.at(-1), { path: target, action: 'verify', directory: false })
  } finally { await rm(root, { recursive: true, force: true }) }
})

for (const platform of ['linux', 'win32']) {
  test(`${platform} writes preserve an existing 0755 parent`, async () => {
    const root = await mkdtemp(join(tmpdir(), 'shodan-parent-'))
    const target = join(root, 'config.json')
    const actions = []
    const options = { platform, acl: (path, action, directory) => { actions.push({ path, action, directory }) } }
    try {
      await chmod(root, 0o755)
      await writePrivate(target, 'original', options)
      assert.equal((await lstat(root)).mode & 0o777, 0o755)
      await writePrivate(target, 'replacement', options)
      assert.equal((await lstat(root)).mode & 0o777, 0o755)
      assert.equal(await readPrivate(target, true, options), 'replacement')
      assert.deepEqual(actions.filter(item => item.directory), [])
    } finally { await rm(root, { recursive: true, force: true }) }
  })
}

test('Unix writes create private directories without changing existing ancestors', async () => {
  const root = await mkdtemp(join(tmpdir(), 'shodan-parent-'))
  const created = join(root, 'private')
  const directory = join(created, 'nested')
  try {
    await chmod(root, 0o755)
    await writePrivate(join(directory, 'config.json'), 'value')
    assert.equal((await lstat(root)).mode & 0o777, 0o755)
    assert.equal((await lstat(created)).mode & 0o777, 0o700)
    assert.equal((await lstat(directory)).mode & 0o777, 0o700)
    assert.equal(await readPrivate(join(directory, 'config.json'), true), 'value')
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
