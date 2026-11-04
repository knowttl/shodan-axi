import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { gunzipSync } from 'node:zlib'
import { test } from 'node:test'
import { withInvestigation } from './investigation-fixture.mjs'

const args = ['scan', 'submit', '192.0.2.7/32', '--allow-operation', 'OP-009,OP-013,OP-015,OP-053', '--accept-unknown-cost', '--scan-credit-budget', '2', '--query-credit-budget', '8', '--max-requests', '10', '--wait', '4', '--limit', '10', '--max-bytes', '10000', '--idle-timeout', '3000']

for (const mode of ['scan-collect', 'scan-collect-cleanup-failed']) test(`targeted scan collection preserves results: ${mode}`, { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, calls, setMode }) => {
    setMode(mode)
    const filename = join(root, 'results.json.gz'); const command = [...args, '--filename', filename]
    const preview = await run(command)
    assert.equal(preview.body.status, 'preview'); assert.ok(preview.body.temporaryAlert)
    assert.equal(calls.length, 0)
    const result = await run([...command, '--execute', '--confirm', preview.body.token])
    assert.equal(result.body.scanId, 'scan-a', JSON.stringify({ result: result.body, calls }))
    assert.equal(result.body.cleanup, mode === 'scan-collect' ? 'completed' : 'failed')
    if (mode !== 'scan-collect') assert.equal(result.body.cleanupAlertId, 'alert-new')
    assert.deepEqual(result.body.events.map(event => event._shodan.id), ['banner-a', 'banner-b'])
    assert.equal(result.body.duplicates, 1); assert.equal(result.body.outOfScope, 1)
    const bytes = await readFile(filename)
    assert.equal(bytes.readUInt32LE(4), 0)
    assert.deepEqual(gunzipSync(bytes).toString().trim().split('\n').map(line => JSON.parse(line)), result.body.events)
    assert.equal(calls.filter(call => call.method === 'POST' && call.path === '/shodan/scan').length, 1)
    assert.equal(calls.filter(call => call.method === 'DELETE' && call.path === '/shodan/alert/alert-new').length, 1)
  })
})

test('internet scan quiet submits once and collection requires the port stream grant', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, calls, setMode }) => {
    setMode('scan-collect')
    const args = ['scan', 'internet', '443', 'https', '--allow-operation', 'OP-010', '--accept-unknown-cost', '--scan-credit-budget', '1', '--max-requests', '1', '--quiet']
    const preview = await run(args)
    const result = await run([...args, '--execute', '--confirm', preview.body.token])
    assert.equal(result.body.scanId, 'scan-internet')
    assert.equal(calls.filter(call => call.method === 'POST' && call.path === '/shodan/scan/internet').length, 1)
    const refused = await run([...args, '--wait', '4', '--limit', '10', '--max-bytes', '10000', '--idle-timeout', '3000'])
    assert.equal(refused.body.error, 'WRITE_GRANT_REQUIRED')
  })
})

test('internet collection selects the requested port and never claims ownership', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, calls, setMode }) => {
    setMode('scan-collect')
    const command = ['scan', 'internet', '443', 'https', '--allow-operation', 'OP-010,OP-049', '--accept-unknown-cost', '--scan-credit-budget', '1', '--max-requests', '2', '--wait', '4', '--limit', '10', '--max-bytes', '10000', '--idle-timeout', '3000']
    const preview = await run(command)
    const result = await run([...command, '--execute', '--confirm', preview.body.token])
    assert.equal(result.body.scanId, 'scan-internet')
    assert.deepEqual(result.body.events.map(event => event._shodan.id), ['banner-a'])
    assert.match(result.body.attribution, /not proof/)
    assert.equal(calls.filter(call => call.path === '/shodan/ports/443').length, 1)
  })
})
