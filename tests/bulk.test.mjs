import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { test } from 'node:test'
import { gunzipSync } from 'node:zlib'
import { withInvestigation } from './investigation-fixture.mjs'

test('dataset listings omit signed URLs', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run }) => {
    assert.equal((await run(['data', 'list'])).body.items[0].name, 'raw-daily')
    const result = await run(['data', 'list', '--dataset', 'raw-daily'])
    assert.equal(result.body.items[0].name, 'synthetic.json')
    assert.doesNotMatch(result.stdout, /signature|127\.0\.0\.1/)
  })
})

test('dataset transfer refuses before credential and metadata access with empty policy', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, calls }) => {
    for (const flags of [[], ['--execute', '--confirm', '00000000-0000-4000-8000-000000000001'], ['--resume'], ['--restart']]) {
      const result = await run(['data', 'download', 'raw-daily', 'synthetic.json', ...flags], { SHODAN_AXI_CONFIG: join(root, 'missing') })
      assert.equal(result.body.error, 'STORAGE_POLICY_UNAVAILABLE')
      assert.match(result.body.message, /host not yet determined/)
    }
    assert.equal(calls.length, 0)
  })
})

for (const { mode, limit, budget } of [
  { mode: 'normal', limit: 2, budget: 1 },
  { mode: 'later-page', limit: 102, budget: 2 },
]) test(`search export confirms and counts ${budget} search requests`, { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, calls, setMode }) => {
    setMode(mode)
    const destination = join(root, 'search.json.gz')
    const args = ['download', 'port:443', '--filename', destination, '--limit', String(limit), '--max-bytes', '100000', '--max-requests', String(budget + 2), '--query-credit-budget', String(budget), '--allow-operation', 'OP-003']
    const preview = await run(args)
    assert.equal(preview.body.status, 'preview', preview.stdout)
    assert.equal(calls.filter(call => call.path === '/shodan/host/search').length, 0)
    const before = calls.length
    const result = await run([...args, '--execute', '--confirm', preview.body.token])
    assert.equal(result.body.requests, calls.length - before)
    assert.equal(result.body.requests, budget)
    assert.equal(result.body.complete, true, result.stdout)
    assert.equal(gunzipSync(await readFile(destination)).toString().trim().split('\n').length, limit)
    assert.equal((await run([...args, '--execute', '--confirm', preview.body.token])).body.error, 'PLAN_NOT_FOUND')
  })
})

for (const selection of [[], ['--alert-id', 'alert-a']]) test(`alert download counts selection requests ${selection.join(' ')}`, { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, calls, setMode }) => {
    setMode('alert-evidence')
    const destination = join(root, 'alerts.json.gz')
    const args = ['alert', 'download', ...selection, '--filename', destination, '--limit', '2', '--max-bytes', '10000', '--max-requests', '4', '--query-credit-budget', '1', '--allow-operation', 'OP-003']
    const preview = await run(args)
    assert.equal(preview.body.status, 'preview', preview.stdout)
    assert.equal(preview.body.query, 'net:192.0.2.0/24')
    assert.equal(calls.filter(call => call.path === '/shodan/host/search').length, 0)
    const before = calls.length
    const result = await run([...args, '--execute', '--confirm', preview.body.token])
    assert.equal(result.body.requests, calls.length - before)
    assert.equal(result.body.requests, 2)
    assert.equal(result.body.complete, true, result.stdout)
    assert.equal(gunzipSync(await readFile(destination)).toString().trim().split('\n').length, 2)
  })
})

for (const { name, limit, budget, total, complete, count } of [
  { name: 'result limit', limit: 2, budget: 2, total: null, complete: false, count: 2 },
  { name: 'credit budget', limit: 100, budget: 1, total: null, complete: false, count: 2 },
  { name: 'all networks visited', limit: 4, budget: 2, total: 4, complete: true, count: 4 },
]) test(`alert export reports selection total with ${name}`, { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, calls, setMode }) => {
    setMode('alert-export-networks')
    const args = ['alert', 'download', '--filename', join(root, 'alerts.json.gz'), '--limit', String(limit), '--max-bytes', '10000', '--max-requests', '6', '--query-credit-budget', String(budget), '--allow-operation', 'OP-003']
    const preview = await run(args)
    assert.equal(preview.body.total, 4, preview.stdout)
    const before = calls.length
    const result = await run([...args, '--execute', '--confirm', preview.body.token])
    assert.equal(result.body.requests, calls.length - before)
    assert.ok(result.body.requests <= 6)
    assert.equal(result.body.total, total, result.stdout)
    assert.equal(result.body.complete, complete, result.stdout)
    assert.equal(result.body.count, count, result.stdout)
    assert.equal(gunzipSync(await readFile(result.body.path)).toString().trim().split('\n').length, count)
  })
})

test('export confirmation binds its destination and respects read-only mode', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, calls }) => {
    const args = ['download', 'port:443', '--filename', join(root, 'first'), '--limit', '2', '--max-bytes', '10000', '--max-requests', '3', '--query-credit-budget', '1', '--allow-operation', 'OP-003']
    const preview = await run(args)
    const altered = args.map(arg => arg === join(root, 'first') ? join(root, 'second') : arg)
    assert.equal((await run([...altered, '--execute', '--confirm', preview.body.token])).body.error, 'PLAN_STALE')
    const readOnly = await run([...args, '--execute', '--confirm', preview.body.token], { SHODAN_AXI_READ_ONLY: 'true', SHODAN_AXI_CONFIG: join(root, 'missing') })
    assert.equal(readOnly.body.error, 'READ_ONLY')
    assert.equal(calls.some(call => call.path === '/shodan/host/search'), false)
  })
})
