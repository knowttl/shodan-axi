import assert from 'node:assert/strict'
import { readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { test } from 'node:test'
import { withInvestigation } from './investigation-fixture.mjs'

test('radar plots confirmed stream points and saves a bounded snapshot', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, calls, setMode }) => {
    setMode('stream-radar')
    const filename = join(root, 'radar.json')
    const args = ['radar', '--allow-operation', 'OP-046', '--accept-unknown-cost', '--limit', '2', '--max-bytes', '10000', '--timeout', '5000', '--idle-timeout', '3000', '--filename', filename]
    const preview = await run(args)
    assert.equal(preview.body.status, 'preview', preview.stdout)
    assert.equal(calls.length, 0)
    const result = await run([...args, '--execute', '--confirm', preview.body.token])
    assert.equal(result.body.stopReason, 'max-events', result.stdout)
    assert.equal(result.body.radar.plottedPoints, 2)
    assert.equal(result.body.radar.ignoredPoints, 0)
    assert.equal(result.body.radar.rows.length, 18)
    assert.ok(result.body.radar.rows.some(row => row.includes('*')))
    assert.deepEqual(JSON.parse(await readFile(filename, 'utf8')), result.body.radar)
  })
})

test('radar refuses an existing destination before opening the stream', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, calls, setMode }) => {
    setMode('stream-radar')
    const filename = join(root, 'existing.json'); await writeFile(filename, 'existing')
    const args = ['radar', '--allow-operation', 'OP-046', '--accept-unknown-cost', '--limit', '2', '--max-bytes', '10000', '--timeout', '5000', '--idle-timeout', '3000', '--filename', filename]
    const preview = await run(args)
    const result = await run([...args, '--execute', '--confirm', preview.body.token])
    assert.equal(result.body.error, 'DESTINATION_EXISTS')
    assert.equal(calls.length, 0)
    assert.equal(await readFile(filename, 'utf8'), 'existing')
  })
})

test('interactive radar quits its stream on q', { timeout: 30000, skip: process.platform === 'win32' }, async () => {
  await withInvestigation(async ({ run, runInteractive, calls, setMode }) => {
    setMode('stream-wait')
    const args = ['radar', '--allow-operation', 'OP-046', '--accept-unknown-cost', '--limit', '2', '--max-bytes', '10000', '--timeout', '5000', '--idle-timeout', '3000']
    const preview = await run(args)
    const result = await runInteractive([...args, '--execute', '--confirm', preview.body.token])
    assert.equal(result.code, 0, result.stdout)
    assert.match(result.stdout, /Press q to stop/)
    assert.match(result.stdout, /stopReason: cancelled/)
    assert.equal(calls.filter(call => call.path === '/shodan/banners').length, 1)
  })
})
