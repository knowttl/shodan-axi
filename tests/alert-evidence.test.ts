import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { test } from 'node:test'
import { gunzipSync } from 'node:zlib'
import { withInvestigation } from './investigation-fixture.ts'

test('alert export writes selected public state without notifier secrets', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, setMode }) => {
    setMode('alert-evidence')
    const file = join(root, 'alerts.json.gz')
    const result = await run(['alert', 'export', '--filename', file])
    assert.equal(result.body.count, 2)
    const data = gunzipSync(await readFile(file)).toString()
    const items = data.trim().split('\n').map(line => JSON.parse(line))
    assert.deepEqual(items.map((item: { id: string }) => item.id), ['alert-a', 'alert-b'])
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
    assert.deepEqual(calls.map(call => call.path), ['/shodan/alert/info', '/shodan/host/count'])
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

test('statistics CSV encodes untrusted facet formulas as literal text', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, setMode }) => {
    setMode('alert-formula-facets')
    const filename = join(root, 'stats.csv')
    const result = await run(['alert', 'stats', '--facets', 'domain', '--filename', filename])
    assert.equal(result.code, 0)
    assert.equal(result.body.items[0].value, '=1+2')
    assert.equal(await readFile(`${filename}.partial`, 'utf8'), "facet,value,count\ndomain,'=1+2,1\n")
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

test('alert statistics reject enumeration flags before credentials or requests', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, calls }) => {
    const env = { SHODAN_AXI_CONFIG: join(root, 'missing-config') }
    for (const flags of [['--exact'], ['--allow-operation', 'OP-003'], ['--query-credit-budget', '1'], ['--max-pages', '1'], ['--max-bytes', '1024']]) {
      const result = await run(['alert', 'stats', ...flags], env)
      assert.equal(result.body.error, 'INVALID_INPUT')
    }
    assert.equal(calls.length, 0)
  })
})
