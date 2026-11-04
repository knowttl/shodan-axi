import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { test } from 'node:test'
import { gunzipSync } from 'node:zlib'
import { withInvestigation } from './investigation-fixture.mjs'

test('alert export writes selected public state without notifier secrets', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, setMode }) => {
    setMode('alert-evidence')
    const file = join(root, 'alerts.json.gz')
    const result = await run(['alert', 'export', '--filename', file])
    assert.equal(result.body.count, 2)
    const data = gunzipSync(await readFile(file)).toString()
    const items = data.trim().split('\n').map(line => JSON.parse(line))
    assert.deepEqual(items.map(item => item.id), ['alert-a', 'alert-b'])
    assert.equal(items[0].notifiers[0].id, 'n1')
    assert.deepEqual(items[0].triggers.any.ignore, [{ ip: '192.0.2.9', port: 80 }])
    assert.doesNotMatch(data + result.stdout, /private-notifier-secret/)
  })
})

test('alert statistics normalize overlap and label top buckets partial', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, calls, setMode }) => {
    setMode('alert-evidence')
    const filename = join(root, 'stats.csv')
    const result = await run(['alert', 'stats', '--facets', 'port:1', '--filename', filename])
    assert.deepEqual(result.body.networks, ['192.0.2.0/24'])
    assert.equal(result.body.aggregation, 'partial')
    assert.equal(result.body.complete, false)
    assert.equal(result.body.saved.path, `${filename}.partial`)
    assert.equal(calls.filter(call => call.path === '/shodan/host/count').length, 1)
  })
})

test('merged truncated facet buckets remain partial across disjoint networks', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, calls, setMode }) => {
    setMode('alert-top-buckets')
    const result = await run(['alert', 'stats', '--facets', 'port:1'])
    assert.deepEqual(result.body.networks, ['192.0.2.0/24', '198.51.100.0/24'])
    assert.equal(result.body.total, 18)
    assert.deepEqual(result.body.items, [{ facet: 'port', value: 443, count: 6 }, { facet: 'port', value: 80, count: 5 }])
    assert.equal(result.body.complete, false)
    assert.equal(calls.filter(call => call.path === '/shodan/host/count').length, 2)
  })
})

test('facet limits apply independently to each facet', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, setMode }) => {
    setMode('alert-multiple-facets')
    const result = await run(['alert', 'stats', '--facets', 'port,country', '--limit', '1'])
    assert.deepEqual(result.body.items, [{ facet: 'port', value: 443, count: 2 }, { facet: 'country', value: 'CA', count: 2 }])
    assert.equal(result.body.complete, false)
  })
})

test('exact statistics require a grant and return bounded partial continuation', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, calls, setMode }) => {
    setMode('alert-exact-partial')
    assert.equal((await run(['alert', 'stats', '--exact'])).body.error, 'CREDIT_BUDGET_REQUIRED')
    assert.equal(calls.length, 0)
    const result = await run(['alert', 'stats', '--exact', '--allow-operation', 'OP-003', '--query-credit-budget', '1', '--max-pages', '1', '--max-requests', '2'])
    assert.equal(result.body.aggregation, 'partial')
    assert.equal(result.body.continuation.page, 2)
    assert.equal(calls.filter(call => call.path === '/shodan/host/search').length, 1)
  })
})

test('exact statistics deduplicate matching service identities', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, setMode }) => {
    setMode('alert-exact-complete')
    const result = await run(['alert', 'stats', '--exact', '--allow-operation', 'OP-003', '--query-credit-budget', '1', '--max-pages', '1', '--max-requests', '2'])
    assert.equal(result.body.complete, true)
    assert.equal(result.body.aggregation, 'exact')
    assert.equal(result.body.total, 2)
    assert.deepEqual(result.body.items, [{ facet: 'port', value: 443, count: 2 }])
  })
})
