import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { test } from 'node:test'
import { gunzipSync } from 'node:zlib'
import { withInvestigation } from './investigation-fixture.mjs'

const grant = id => ['--allow-operation', id, '--query-credit-budget', '1', '--accept-unknown-cost', '--max-requests', '1']

test('community directory preserves query fields and selected parameters', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, calls }) => {
    const list = await run(['query', 'list', '--page', '2', '--sort', 'votes', '--order', 'asc'])
    assert.equal(list.code, 0)
    assert.deepEqual(list.body.items, [{ title: 'Synthetic TLS', query: 'port:443', votes: 3 }])
    assert.equal(list.body.total, 11)
    assert.equal(list.body.complete, false)
    assert.deepEqual(calls.at(-1).query, { key: 'fake-secret', page: '2', sort: 'votes', order: 'asc' })
    assert.equal((await run(['query', 'search', 'Synthetic TLS', '--page', '1'])).body.items[0].query, 'port:443')
    assert.deepEqual((await run(['query', 'tags', '--size', '2'])).body.items, [{ value: 'test', count: 3 }, { value: 'tls', count: 2 }])
  })
})

test('trends joins facets by month and saves matching records', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, calls }) => {
    assert.deepEqual((await run(['trends', 'filters'])).body.items, ['all', 'asn', 'has_ipv6'])
    assert.deepEqual((await run(['trends', 'facets'])).body.items, ['asn', 'country', 'vuln.verified'])
    const result = await run(['trends', 'port:443', '--facets', 'country:2', '--filename', 'trends', ...grant('OP-054')])
    assert.equal(result.code, 0)
    assert.deepEqual(result.body.months, [{ month: '2026-09', count: 3, country: [{ value: 'US', count: 3 }] }, { month: '2026-10', count: 4, country: [{ value: 'CA', count: 4 }] }])
    assert.deepEqual(gunzipSync(await readFile(join(root, 'trends.json.gz'))).toString().trim().split('\n').map(JSON.parse), [
      { month: '2026-09', count: 3, facets: { country: [{ value: 'US', count: 3 }] } },
      { month: '2026-10', count: 4, facets: { country: [{ value: 'CA', count: 4 }] } },
    ])
    assert.deepEqual(calls.at(-1).query, { key: 'fake-secret', query: 'port:443', facets: 'country:2' })
    assert.equal((await run(['trends', 'port:443', '--save', ...grant('OP-054')])).code, 0)
    assert.equal(gunzipSync(await readFile(join(root, 'port:443-trends.json.gz'))).toString().trim().split('\n').length, 2)
    const before = calls.length
    assert.equal((await run(['trends', 'port:443'])).body.error, 'CREDIT_BUDGET_REQUIRED')
    assert.equal(calls.length, before)
  })
})

test('exploit contracts preserve results, bound text and distinguish denial from redirect', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, calls, setMode }) => {
    const result = await run(['exploits', 'search', 'cve:2020-0001', '--page', '1', '--facets', 'source', ...grant('OP-057')])
    assert.equal(result.body.items[0]._id, '2020-0001')
    assert.equal(result.body.items[0].description.length, 503)
    assert.equal(result.body.truncations[0].length, 600)
    assert.equal((await run(['exploits', 'search', 'cve:2020-0001', '--full', ...grant('OP-057')])).body.items[0].description.length, 600)
    assert.equal((await run(['exploits', 'count', 'cve:2020-0001', '--facets', 'source', ...grant('OP-058')])).body.total, 1)
    assert.equal(calls.at(-1).path, '/api/count')
    setMode('denied')
    assert.equal((await run(['trends', 'filters'])).body.error, 'ACCESS_DENIED')
    setMode('redirect')
    assert.equal((await run(['exploits', 'count', 'cve:2020-0001', ...grant('OP-058')])).body.error, 'REDIRECT_REFUSED')
  })
})
