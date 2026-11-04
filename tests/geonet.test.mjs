import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { test } from 'node:test'
import { withInvestigation } from './investigation-fixture.mjs'

for (const [command, target, operation] of [
  ['ping', '192.0.2.7', 'OP-060'], ['geoping', '192.0.2.7', 'OP-061'],
  ['dns', 'service.example.test', 'OP-062'], ['geodns', 'service.example.test', 'OP-063'],
]) test(`${command} requires confirmation and preserves observer data without credentials`, { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, calls }) => {
    const args = ['geonet', command, target, ...(command.includes('dns') ? ['--type', 'A'] : []), '--allow-operation', operation, '--max-requests', '1']
    const noAuth = { SHODAN_AXI_CONFIG: join(root, 'missing.json'), TEST_SHODAN_KEY: '' }
    const preview = await run(args, noAuth)
    assert.equal(preview.body.status, 'preview')
    assert.equal(preview.body.target, target)
    assert.equal(preview.body.locations, 'service-selected')
    assert.equal(calls.length, 0)
    assert.equal((await run([...args, '--execute', '--confirm', preview.body.token], { ...noAuth, SHODAN_AXI_READ_ONLY: 'true' })).body.error, 'READ_ONLY')
    const result = await run([...args, '--execute', '--confirm', preview.body.token], noAuth)
    assert.equal(result.code, 0)
    assert.equal(calls.length, 1)
    assert.equal(calls[0].method, 'GET')
    assert.equal(calls[0].query.key, undefined)
    if (command.includes('dns')) assert.equal(calls[0].query.rtype, 'A')
    if (command === 'ping') assert.equal(result.body.avg_rtt, 6)
    if (command === 'geoping') { assert.equal(result.body.observers, 2); assert.equal(result.body.items[1].is_alive, false); assert.equal(result.body.items[1].packet_loss, 1) }
    if (command === 'dns') assert.equal(result.body.answers[0].value, '192.0.2.7')
    if (command === 'geodns') { assert.equal(result.body.observers, 2); assert.deepEqual(result.body.items[1].answers, []) }
    assert.equal((await run([...args, '--execute', '--confirm', preview.body.token], noAuth)).body.error, 'PLAN_NOT_FOUND')
    assert.equal(calls.length, 1)
  })
})

test('probe confirmation binds target and a lost response is never retried', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, calls, setMode }) => {
    const args = ['geonet', 'geoping', '192.0.2.7', '--allow-operation', 'OP-061', '--max-requests', '1']
    const preview = await run(args)
    assert.equal((await run(['geonet', 'geoping', '192.0.2.8', ...args.slice(3), '--execute', '--confirm', preview.body.token])).body.error, 'PLAN_STALE')
    assert.equal(calls.length, 0)
    setMode('probe-lost')
    const result = await run([...args, '--execute', '--confirm', preview.body.token])
    assert.equal(result.body.error, 'OUTCOME_UNKNOWN')
    assert.equal(calls.length, 1)
    assert.match(await readFile(join(root, '.local/state/shodan-axi/writes.log'), 'utf8'), /OUTCOME_UNKNOWN/)
  })
})

test('probe grants and DNS record type are bound before any request', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, calls }) => {
    assert.equal((await run(['geonet', 'dns', 'service.example.test', '--max-requests', '1'])).body.error, 'WRITE_GRANT_REQUIRED')
    const args = ['geonet', 'dns', 'service.example.test', '--type', 'A', '--allow-operation', 'OP-062', '--max-requests', '1']
    const preview = await run(args)
    const changed = ['geonet', 'dns', 'service.example.test', '--type', 'AAAA', '--allow-operation', 'OP-062', '--max-requests', '1', '--execute', '--confirm', preview.body.token]
    assert.equal((await run(changed)).body.error, 'PLAN_STALE')
    assert.equal(calls.length, 0)
  })
})
