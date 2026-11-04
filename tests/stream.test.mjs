import assert from 'node:assert/strict'
import { mkdir, readFile, readdir, symlink } from 'node:fs/promises'
import { join } from 'node:path'
import { test } from 'node:test'
import { gunzipSync } from 'node:zlib'
import { withInvestigation } from './investigation-fixture.mjs'

const selections = [
  [['stream'], 'OP-046', '/shodan/banners'],
  [['stream', '--asn', '64500,64501'], 'OP-047', '/shodan/asn/64500,64501'],
  [['stream', '--countries', 'CA,US'], 'OP-048', '/shodan/countries/CA,US'],
  [['stream', '--ports', '443,8443'], 'OP-049', '/shodan/ports/443,8443'],
  [['stream', '--vulns', 'CVE-2020-0001'], 'OP-050', '/shodan/vulns/CVE-2020-0001'],
  [['stream', '--custom-filters', 'port:443'], 'OP-051', '/shodan/custom'],
  [['stream', '--alert', 'all'], 'OP-052', '/shodan/alert'],
  [['stream', '--alert', 'alert-a'], 'OP-053', '/shodan/alert/alert-a'],
  [['stream', '--tags', 'self-signed'], 'OP-065', '/shodan/tags/self-signed'],
  [['threatnet', 'events'], 'OP-067', '/threatnet/events'],
  [['threatnet', 'backscatter'], 'OP-068', '/threatnet/backscatter'],
  [['threatnet', 'ssh'], 'OP-069', '/threatnet/ssh'],
]
const options = operation => ['--allow-operation', operation, '--accept-unknown-cost', '--limit', '2', '--max-bytes', '10000', '--timeout', '5000', '--idle-timeout', '3000']

test('each stream selector uses one confirmed connection and preserves framed events', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, calls, setMode }) => {
    setMode('stream-json')
    for (const [command, operation, path] of selections) {
      const before = calls.length
      const args = [...command, ...options(operation)]
      const preview = await run(args)
      assert.equal(preview.body.status, 'preview', preview.stdout)
      assert.equal(calls.length, before)
      const result = await run([...args, '--execute', '--confirm', preview.body.token])
      assert.equal(result.body.stopReason, 'max-events', result.stdout)
      assert.equal(result.body.count, 2)
      assert.equal(result.body.debugDiscarded, 3)
      assert.equal(result.body.partialRecordCount, 0)
      assert.equal(calls.length, before + 1)
      assert.equal(calls.at(-1).path, path)
      assert.equal(result.body.events[0].data ?? result.body.events[0].text, 'Café')
      if (command[0] === 'threatnet') assert.equal(result.body.domainSchemaValidated, false)
    }
  })
})

test('SSE framing, incomplete records and malformed records are distinct', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, setMode }) => {
    const args = ['stream', ...options('OP-046')]
    for (const [mode, expected] of [['stream-sse', 'max-events'], ['stream-partial', 'upstream-eof']]) {
      setMode(mode)
      const preview = await run(args)
      const result = await run([...args, '--execute', '--confirm', preview.body.token])
      assert.equal(result.body.stopReason, expected, result.stdout)
      assert.equal(result.body.partialRecordCount, mode === 'stream-partial' ? 1 : 0)
    }
    setMode('stream-malformed')
    const preview = await run(args)
    assert.equal((await run([...args, '--execute', '--confirm', preview.body.token])).body.error, 'INVALID_RESPONSE')
  })
})

test('read-only mode and conflicting selectors fail before credentials or requests', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, calls }) => {
    const args = ['stream', ...options('OP-046')]
    const env = { SHODAN_AXI_CONFIG: join(root, 'missing'), SHODAN_AXI_READ_ONLY: 'true' }
    assert.equal((await run([...args, '--execute', '--confirm', '00000000-0000-4000-8000-000000000001'], env)).body.error, 'READ_ONLY')
    assert.equal((await run([...args, '--asn', '1', '--ports', '443'], env)).body.error, 'INVALID_INPUT')
    assert.equal(calls.length, 0)
  })
})

test('follow writes bounded gzip records and retains selected files', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, setMode }) => {
    setMode('stream-json')
    const directory = join(root, 'stream-output')
    const args = ['stream', ...options('OP-046'), '--follow', '--datadir', directory, '--max-file-bytes', '150', '--retain', '1', '--compresslevel', '1']
    const preview = await run(args)
    const result = await run([...args, '--execute', '--confirm', preview.body.token])
    assert.equal(result.body.stopReason, 'max-events', result.stdout)
    const files = await readdir(directory)
    assert.equal(files.length, 1)
    const compressed = await readFile(join(directory, files[0]))
    assert.equal(compressed[8], 4)
    assert.ok(compressed.length <= 150)
    const records = gunzipSync(compressed).toString().trim().split('\n').map(line => JSON.parse(line))
    assert.equal(records.at(-1).ip_str, '192.0.2.8')
  })
})

test('follow rejects a symlinked output directory before connecting', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, calls, setMode }) => {
    setMode('stream-json')
    const directory = join(root, 'real-directory'); const link = join(root, 'indirect')
    await mkdir(directory, { mode: 0o700 }); await symlink(directory, link, 'dir')
    const args = ['stream', ...options('OP-046'), '--follow', '--datadir', link, '--max-file-bytes', '1000', '--retain', '1']
    const preview = await run(args)
    const result = await run([...args, '--execute', '--confirm', preview.body.token])
    assert.equal(result.body.error, 'CONFIG_INSECURE')
    assert.equal(calls.length, 0)
  })
})

test('idle streams stop at the selected idle timeout', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, setMode }) => {
    setMode('stream-idle')
    const args = ['stream', ...options('OP-046').map(value => value === '3000' ? '500' : value)]
    const preview = await run(args)
    const result = await run([...args, '--execute', '--confirm', preview.body.token])
    assert.equal(result.body.stopReason, 'idle-timeout', result.stdout)
    assert.equal(result.body.count, 0)
  })
})

test('cancelling follow closes the connection after the last complete event', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, setMode }) => {
    setMode('stream-wait')
    const args = ['stream', ...options('OP-046'), '--follow', '--datadir', join(root, 'follow'), '--max-file-bytes', '1000', '--retain', '1']
    const preview = await run(args)
    const result = await run([...args, '--execute', '--confirm', preview.body.token], {}, child => { child.stdout.once('data', () => { child.kill('SIGINT') }) })
    assert.equal(result.body.stopReason, 'cancelled', result.stdout)
    assert.equal(result.body.count, 1)
  })
})

test('stream byte bounds and upstream denials never fabricate events', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, setMode }) => {
    setMode('stream-json')
    const args = ['stream', ...options('OP-046').map(value => value === '10000' ? '10' : value)]
    const preview = await run(args)
    const result = await run([...args, '--execute', '--confirm', preview.body.token])
    assert.equal(result.body.stopReason, 'max-bytes', result.stdout)
    assert.equal(result.body.count, 0)
    setMode('stream-denied')
    const deniedPreview = await run(args)
    assert.equal((await run([...args, '--execute', '--confirm', deniedPreview.body.token])).body.error, 'UPSTREAM_ERROR')
    assert.equal((await run([...args, '--execute', '--confirm', deniedPreview.body.token])).body.error, 'PLAN_NOT_FOUND')
  })
})
