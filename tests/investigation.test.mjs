import assert from 'node:assert/strict'
import { readFile, symlink, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { test } from 'node:test'
import { gunzipSync } from 'node:zlib'
import { withInvestigation } from './investigation-fixture.mjs'

test('redaction preserves public result keys across output and artifacts', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run }) => {
    assert.equal((await run(['dns', 'resolve', 'monkey.example'])).body['monkey.example'], '192.0.2.7')
    const count = await run(['count', 'port:443', '--facets', 'key:2'])
    assert.deepEqual(count.body.facets.key, [{ value: 443, count: 1 }, { value: 80, count: 1 }])
    const stats = await run(['stats', 'port:443', '--facets', 'ssl.cert.pubkey.bits:2'])
    assert.equal(stats.body.facets['ssl.cert.pubkey.bits'][0].value, 443)
    const selected = await run(['search', 'port:443', '--fields', 'ssl.cert.pubkey.bits', '--allow-operation', 'OP-003', '--query-credit-budget', '1'])
    assert.deepEqual(selected.body.items, [{ 'ssl.cert.pubkey.bits': 2048 }, { 'ssl.cert.pubkey.bits': 2048 }])
    const host = await run(['host', '192.0.2.7', '--save'])
    assert.equal(host.body.host.data[0].ssl.cert.pubkey.bits, 2048)
    assert.equal(host.body.banners[0].ssl.cert.pubkey.bits, 2048)
    assert.equal(host.body.banners[0].data, 'synthetic banner [REDACTED]')
    const saved = gunzipSync(await readFile(join(root, '192.0.2.7.json.gz'))).toString()
    assert.equal(JSON.parse(saved.trim().split('\n')[0]).ssl.cert.pubkey.bits, 2048)
    assert.doesNotMatch(saved, /fake-secret/)
    const domain = await run(['domain', 'example.test', '--details', '--save', '--max-requests', '2', '--allow-operation', 'OP-040', '--query-credit-budget', '1'])
    assert.equal(domain.body.details[0].data[0].ssl.cert.pubkey.bits, 2048)
    const enriched = gunzipSync(await readFile(join(root, 'example.test-hosts.json.gz'))).toString()
    assert.equal(JSON.parse(enriched.trim().split('\n')[0]).ssl.cert.pubkey.bits, 2048)
    assert.doesNotMatch(enriched, /fake-secret/)
    const headers = await run(['tools', 'headers'])
    assert.equal(headers.body.Authorization, '[REDACTED]')
    assert.equal(headers.body['Proxy-Authorization'], '[REDACTED]')
  })
})

test('minified host reads accept missing banners without weakening full reads', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, calls, run, setMode }) => {
    for (const format of [[], ['--format', 'tsv'], ['--format', 'pretty']]) {
      const result = await run(['host', '192.0.2.7', '--minify', 'true', ...format])
      assert.equal(result.code, 0)
      assert.deepEqual(result.body.host.ports, [443])
      assert.deepEqual(result.body.banners, [])
      assert.equal(calls.at(-1).query.minify, 'true')
    }
    const saved = await run(['host', '192.0.2.7', '--minify', 'true', '--save'])
    assert.equal(saved.code, 0)
    assert.equal(gunzipSync(await readFile(join(root, '192.0.2.7.json.gz'))).toString(), '\n')
    setMode('missing-banners')
    assert.equal((await run(['host', '192.0.2.7'])).body.error, 'INVALID_RESPONSE')
    assert.equal((await run(['host', '192.0.2.7', '--minify', 'false'])).body.error, 'INVALID_RESPONSE')
    assert.equal((await run(['domain', 'example.test', '--details', '--max-requests', '2', '--allow-operation', 'OP-040', '--query-credit-budget', '1'])).body.error, 'INVALID_RESPONSE')
  })
})

test('search stops at the global total when resuming a page', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ calls, run, setMode }) => {
    for (const [mode, page, offset, count] of [['normal', '1', '1', 1], ['normal', '1', '2', 0], ['later-page', '2', '0', 2], ['later-page', '2', '1', 1], ['later-page', '2', '2', 0]]) {
      setMode(mode)
      const before = calls.length
      const result = await run(['search', 'port:443', '--page', page, '--offset', offset, '--max-pages', '2', '--max-requests', '2', '--allow-operation', 'OP-003', '--query-credit-budget', '2'])
      assert.equal(result.code, 0)
      assert.equal(result.body.count, count)
      assert.equal(calls.length, before + 1)
      assert.equal(result.body.continuation, undefined)
      assert.equal(result.body.complete, false)
      assert.equal(result.body.stopReason, 'exhausted')
    }
    setMode('later-page')
    const clipped = await run(['search', 'port:443', '--page', '2', '--limit', '1', '--allow-operation', 'OP-003', '--query-credit-budget', '1'])
    assert.deepEqual(clipped.body.continuation, { page: 2, offset: 1 })
    assert.equal(clipped.body.stopReason, 'limit')
    const before = calls.length
    const multiple = await run(['search', 'port:443', '--limit', '101', '--max-pages', '3', '--max-requests', '3', '--allow-operation', 'OP-003', '--query-credit-budget', '3'])
    assert.equal(multiple.body.count, 101)
    assert.deepEqual(multiple.body.continuation, { page: 2, offset: 1 })
    assert.equal(calls.length, before + 2)
    const beforeResumed = calls.length
    const resumed = await run(['search', 'port:443', '--offset', '99', '--max-pages', '3', '--max-requests', '3', '--allow-operation', 'OP-003', '--query-credit-budget', '3'])
    assert.equal(resumed.body.count, 3)
    assert.equal(resumed.body.continuation, undefined)
    assert.equal(resumed.body.stopReason, 'exhausted')
    assert.equal(calls.length, beforeResumed + 2)
  })
})

test('host reads preserve distinct banners and write redacted verified files', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, calls, run, setMode }) => {
    const host = await run(['host', '192.0.2.7', '--history', '--minify', 'false'])
    assert.equal(host.code, 0)
    assert.deepEqual(host.body.banners.map(item => [item.transport, item.timestamp]), [['tcp', '2026-01-01'], ['udp', '2026-01-02'], ['tcp', '2026-01-03']])
    assert.deepEqual(host.body.vendorTruncations, ['http.html'])
    assert.equal(host.body.fullHistoricalPayload, false)
    assert.deepEqual(calls.at(-1).query, { key: 'fake-secret', history: 'true', minify: 'false' })
    assert.match((await run(['host', '192.0.2.7', '--format', 'tsv'])).body.display, /192\.0\.2\.7\t443\ttcp\t2026-01-01/)
    assert.equal((await run(['host', '192.0.2.7', '--format', 'pretty'])).code, 0)
    assert.equal((await run(['host', '192.0.2.7', '--save'])).code, 0)
    assert.equal(gunzipSync(await readFile(join(root, '192.0.2.7.json.gz'))).toString().trim().split('\n').length, 3)
    const savePath = join(root, 'host.json.gz')
    setMode('placeholder')
    assert.equal((await run(['host', '192.0.2.7', '--filename', savePath])).code, 0)
    const saved = gunzipSync(await readFile(savePath)).toString()
    assert.equal(saved.trim().split('\n').length, 3)
    assert.doesNotMatch(saved, /fake-secret/)
    assert.doesNotMatch(saved, /placeholder/)
    const target = join(root, 'protected')
    await writeFile(target, 'unchanged', { mode: 0o600 })
    const link = join(root, 'link.json.gz')
    await symlink(target, link)
    assert.notEqual((await run(['host', '192.0.2.7', '--filename', link])).code, 0)
    assert.equal(await readFile(target, 'utf8'), 'unchanged')
  })
})

test('search preserves page totals and enforces independent request and credit limits', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, calls, run, setMode }) => {
    const before = calls.length
    assert.equal((await run(['search', 'port:443'])).body.error, 'CREDIT_BUDGET_REQUIRED')
    assert.equal((await run(['domain', 'a..example', '--allow-operation', 'OP-040', '--query-credit-budget', '1'], { SHODAN_AXI_CONFIG: join(root, 'missing') })).body.error, 'INVALID_INPUT')
    assert.equal((await run(['search', 'port:443', '--fields', 'ip_str,,port', '--allow-operation', 'OP-003', '--query-credit-budget', '1'], { SHODAN_AXI_CONFIG: join(root, 'missing') })).body.error, 'INVALID_INPUT')
    assert.equal(calls.length, before)
    setMode('empty')
    const empty = await run(['search', 'ip:192.0.2.7', '--allow-operation', 'OP-003', '--query-credit-budget', '1'])
    assert.deepEqual([empty.code, empty.body.count, empty.body.total, empty.body.complete, empty.body.items], [0, 0, 0, true, []])
    setMode('normal')
    const second = await run(['search', 'port:443', '--page', '2', '--fields', 'ip_str,port', '--allow-operation', 'OP-003', '--query-credit-budget', '1'])
    assert.deepEqual([second.body.total, second.body.count, second.body.complete, second.body.stopReason], [2, 0, false, 'empty-page'])
    const first = await run(['search', 'port:443', '--limit', '1', '--fields', 'ip_str,port', '--allow-operation', 'OP-003', '--query-credit-budget', '1'])
    assert.deepEqual(first.body.items, [{ ip_str: '192.0.2.7', port: 443 }])
    assert.deepEqual(first.body.continuation, { page: 1, offset: 1 })
    const resumed = await run(['search', 'port:443', '--page', '1', '--offset', '1', '--limit', '1', '--fields', 'transport', '--allow-operation', 'OP-003', '--query-credit-budget', '1'])
    assert.deepEqual(resumed.body.items, [{ transport: 'udp' }])
    setMode('multipage')
    const beforePages = calls.length
    const limited = await run(['search', 'port:443', '--max-pages', '2', '--max-requests', '2', '--allow-operation', 'OP-003', '--query-credit-budget', '1'])
    assert.equal(calls.length, beforePages + 1)
    assert.equal(limited.body.stopReason, 'credit-budget')
    assert.deepEqual(limited.body.continuation, { page: 2, offset: 0 })
    const all = await run(['search', 'port:443', '--max-pages', '2', '--max-requests', '2', '--allow-operation', 'OP-003', '--query-credit-budget', '2'])
    assert.deepEqual([all.body.count, all.body.complete], [2, true])
    const beforeRequests = calls.length
    const requestLimited = await run(['search', 'port:443', '--max-pages', '2', '--max-requests', '1', '--allow-operation', 'OP-003', '--query-credit-budget', '2'])
    assert.equal(requestLimited.body.stopReason, 'request-limit')
    assert.equal(calls.length, beforeRequests + 1)
  })
})

test('search projects nested fields and exposes text truncation and display options', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, setMode }) => {
    const display = await run(['search', 'port:443', '--limit', '1', '--fields', 'ip_str,location.country_code', '--separator', '|', '--no-color', '--allow-operation', 'OP-003', '--query-credit-budget', '1'])
    assert.equal(display.body.display, '192.0.2.7|CA')
    const colored = await run(['search', 'port:443', '--limit', '1', '--fields', 'ip_str', '--color', '--allow-operation', 'OP-003', '--query-credit-budget', '1'])
    assert.match(colored.body.display, /\u001b\[36m/)
    setMode('long')
    const abbreviated = await run(['search', 'port:443', '--allow-operation', 'OP-003', '--query-credit-budget', '1'])
    assert.equal(abbreviated.body.truncations[0].length, 600)
    const full = await run(['search', 'port:443', '--full', '--allow-operation', 'OP-003', '--query-credit-budget', '1'])
    assert.equal(full.body.items[0].data.length, 600)
  })
})

test('terminal domain reads distinguish exhaustion from budget termination', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ calls, run, setMode }) => {
    const grant = ['--allow-operation', 'OP-040', '--query-credit-budget', '1']
    setMode('domain-terminal')
    for (const [page, offset, count, reason] of [['2', '0', 2, 'exhausted'], ['1', '1', 1, 'exhausted'], ['2', '1', 1, 'exhausted'], ['1', '2', 0, 'exhausted'], ['1', '0', 2, 'complete']]) {
      const before = calls.length
      const result = await run(['domain', 'example.test', '--page', page, '--offset', offset, ...grant])
      assert.equal(result.code, 0)
      assert.equal(result.body.count, count)
      assert.equal(result.body.stopReason, reason)
      assert.equal(result.body.complete, reason === 'complete')
      assert.equal(result.body.continuation, undefined)
      assert.equal(result.body.nextPage, undefined)
      assert.equal(calls.length, before + 1)
    }
    const clipped = await run(['domain', 'example.test', '--page', '2', '--limit', '1', ...grant])
    assert.equal(clipped.body.stopReason, 'limit')
    assert.deepEqual(clipped.body.continuation, { page: 2, offset: 1 })
    const unfinished = await run(['domain', 'example.test', '--page', '2', '--details', ...grant])
    assert.equal(unfinished.body.stopReason, 'request-limit')
    assert.deepEqual(unfinished.body.remainingDetails, ['192.0.2.7'])
    const enriched = await run(['domain', 'example.test', '--page', '2', '--details', '--save', '--max-requests', '2', ...grant])
    assert.equal(enriched.body.stopReason, 'exhausted')
    assert.equal(enriched.body.details.length, 1)
    assert.equal(enriched.body.complete, false)
    assert.equal(enriched.body.continuation, undefined)
    setMode('domain-empty-terminal')
    const empty = await run(['domain', 'example.test', '--page', '2', ...grant])
    assert.equal(empty.body.stopReason, 'exhausted')
    assert.deepEqual(empty.body.records, [])
    assert.equal(empty.body.continuation, undefined)
  })
})

test('domain enrichment preserves DNS records when hosts are not indexed', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, calls, run, setMode }) => {
    const grant = ['--allow-operation', 'OP-040', '--query-credit-budget', '1']
    const missing = [{ ip_str: '192.0.2.8', status: 'not-indexed' }, { ip_str: '2001:db8::8', status: 'not-indexed' }]
    setMode('domain-unindexed')
    const limited = await run(['domain', 'example.test', '--details', '--max-requests', '2', ...grant])
    assert.equal(limited.code, 0)
    assert.equal(limited.body.records.length, 3)
    assert.deepEqual(limited.body.details, missing.slice(0, 1))
    assert.deepEqual(limited.body.remainingDetails, ['2001:db8::8', '192.0.2.7'])
    assert.equal(limited.body.stopReason, 'request-limit')
    const before = calls.length
    const result = await run(['domain', 'example.test', '--details', '--save', '--max-requests', '4', ...grant])
    assert.equal(result.code, 0)
    assert.deepEqual(result.body.records, [{ type: 'A', value: '192.0.2.8' }, { type: 'AAAA', value: '2001:db8::8' }, { type: 'A', value: '192.0.2.7' }])
    assert.deepEqual(result.body.details.slice(0, 2), missing)
    assert.equal(result.body.details[2].ip_str, '192.0.2.7')
    assert.equal(result.body.complete, true)
    assert.equal(result.body.stopReason, 'complete')
    assert.equal(result.body.continuation, undefined)
    assert.equal(result.body.remainingDetails, undefined)
    assert.equal(calls.length, before + 4)
    const records = gunzipSync(await readFile(join(root, 'example.test.json.gz'))).toString().trim().split('\n').map(row => JSON.parse(row))
    assert.deepEqual(records, result.body.records)
    const banners = gunzipSync(await readFile(join(root, 'example.test-hosts.json.gz'))).toString().trim().split('\n').map(row => JSON.parse(row))
    assert.equal(banners.length, 3)
    assert.deepEqual(banners.map(row => row.ip_str), ['192.0.2.7', '192.0.2.7', '192.0.2.7'])
    assert.equal((await run(['host', '192.0.2.8'])).body.error, 'NOT_FOUND')
    setMode('domain-enrichment-denied')
    assert.equal((await run(['domain', 'example.test', '--details', '--max-requests', '4', ...grant])).body.error, 'UPSTREAM_ERROR')
  })
})

test('domain enrichment and saves cover only selected records', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, calls, run, setMode }) => {
    const domain = await run(['domain', 'example.test', '--type', 'A', '--allow-operation', 'OP-040', '--query-credit-budget', '1'])
    assert.equal(domain.body.records[0].value, '192.0.2.7')
    assert.equal(domain.body.nextPage, 2)
    assert.deepEqual(calls.at(-1).query, { key: 'fake-secret', type: 'A', page: '1', history: 'false' })
    const before = calls.length
    const detailed = await run(['domain', 'example.test', '--details', '--max-requests', '2', '--allow-operation', 'OP-040', '--query-credit-budget', '1'])
    assert.equal(detailed.body.details.length, 1)
    assert.deepEqual(calls.slice(before).map(call => call.path), ['/dns/domain/example.test', '/shodan/host/192.0.2.7'])
    const limited = await run(['domain', 'example.test', '--details', '--allow-operation', 'OP-040', '--query-credit-budget', '1'])
    assert.deepEqual(limited.body.remainingDetails, ['192.0.2.7'])
    assert.equal(limited.body.stopReason, 'request-limit')
    setMode('domain-many')
    const beforeClipped = calls.length
    const clipped = await run(['domain', 'example.test', '--details', '--limit', '1', '--max-requests', '2', '--allow-operation', 'OP-040', '--query-credit-budget', '1'])
    assert.equal(clipped.body.records.length, 1)
    assert.deepEqual(clipped.body.continuation, { page: 1, offset: 1 })
    assert.deepEqual(calls.slice(beforeClipped).map(call => call.path), ['/dns/domain/example.test', '/shodan/host/192.0.2.7'])
    setMode('domain-txt')
    const beforeTyped = calls.length
    const typed = await run(['domain', 'example.test', '--details', '--max-requests', '3', '--allow-operation', 'OP-040', '--query-credit-budget', '1'])
    assert.equal(typed.body.details.length, 1)
    assert.deepEqual(calls.slice(beforeTyped).map(call => call.path), ['/dns/domain/example.test', '/shodan/host/192.0.2.7'])
    setMode('normal')
    assert.equal((await run(['domain', 'example.test', '-H', '-T', 'A', '-D', '-S', '--max-requests', '2', '--allow-operation', 'OP-040', '--query-credit-budget', '1'])).code, 0)
    assert.equal(calls.at(-2).query.history, 'true')
    assert.equal(JSON.parse(gunzipSync(await readFile(join(root, 'example.test.json.gz'))).toString()).type, 'A')
    assert.equal(gunzipSync(await readFile(join(root, 'example.test-hosts.json.gz'))).toString().trim().split('\n').length, 3)
  })
})

test('free catalogues, DNS and statistics preserve returned values', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run }) => {
    const count = await run(['count', 'port:443', '--facets', 'port:2'])
    assert.equal(count.body.total, 2)
    assert.equal(count.body.facets.port[0].value, 443)
    assert.deepEqual((await run(['search', 'facets'])).body.items, ['port', 'country'])
    assert.deepEqual((await run(['search', 'filters'])).body.items, ['asn', 'port'])
    assert.deepEqual((await run(['search', 'tokens', 'port:443'])).body.attributes.ports, [443])
    assert.deepEqual((await run(['ports'])).body.items, [22, 443])
    const filename = join(root, 'stats.csv')
    assert.equal((await run(['stats', 'net:192.0.2.0/24', '--facets', 'port:2', '--filename', filename])).body.count, 2)
    assert.equal((await readFile(filename, 'utf8')).trim().split('\n').length, 2)
    assert.equal((await run(['dns', 'resolve', 'example.test,missing.example.test'])).body['missing.example.test'], null)
    assert.deepEqual((await run(['dns', 'reverse', '192.0.2.7,192.0.2.8'])).body['192.0.2.8'], [])
    assert.doesNotMatch((await run(['tools', 'headers'])).stdout, /fake-secret/)
  })
})

test('public and IPv6 reads preserve credential and transport boundaries', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, calls, run }) => {
    assert.equal((await run(['myip'])).body.addressFamily, 4)
    assert.equal((await run(['myip', '--ipv6'])).body.addressFamily, 6)
    const before = calls.length
    assert.equal((await run(['myip', '--ipv6'], { TEST_FAIL_V6: '1' })).body.error, 'UPSTREAM_ERROR')
    assert.equal(calls.length, before)
    const invalid = join(root, 'invalid.json')
    await writeFile(invalid, JSON.stringify({ version: 1, profiles: { invalid: { auth: 'api-key', apiKey: 'inline-secret' } } }), { mode: 0o600 })
    const publicRead = await run(['internetdb', 'host', '192.0.2.7'], { SHODAN_AXI_CONFIG: invalid, SHODAN_AXI_PROFILE: 'invalid' })
    assert.deepEqual(publicRead.body.vulns, ['CVE-2020-0001'])
    assert.equal(calls.at(-1).query.key, undefined)
    const noAuth = join(root, 'none.json')
    await writeFile(noAuth, JSON.stringify({ version: 1, profiles: { none: { auth: 'none' } } }), { mode: 0o600 })
    const beforeNoAuth = calls.length
    assert.equal((await run(['count', 'port:443', '--config', noAuth, '--profile', 'none'])).body.error, 'AUTH_REQUIRED')
    assert.equal(calls.length, beforeNoAuth)
  })
})

test('unknown-cost and failing requests do not bypass budgets or retry', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ calls, run, setMode }) => {
    const before = calls.length
    assert.equal((await run(['honeyscore', '192.0.2.7', '--allow-operation', 'OP-064', '--accept-unknown-cost', '--max-requests', '1'])).body.error, 'CREDIT_BUDGET_REQUIRED')
    assert.equal(calls.length, before)
    assert.equal((await run(['honeyscore', '192.0.2.7', '--allow-operation', 'OP-064', '--accept-unknown-cost', '--max-requests', '1', '--query-credit-budget', '1'])).body.score, 0.25)
    assert.equal((await run(['services', '--allow-operation', 'OP-066', '--accept-unknown-cost', '--max-requests', '1', '--query-credit-budget', '1'])).body.contractStatus, 'source-only-unverified')
    setMode('denied')
    assert.equal((await run(['ports'])).body.error, 'UPSTREAM_ERROR')
    setMode('malformed')
    assert.equal((await run(['ports'])).body.error, 'INVALID_RESPONSE')
    setMode('bad-port')
    assert.equal((await run(['ports'])).body.error, 'INVALID_RESPONSE')
    setMode('normal')
    assert.equal((await run(['ports', '--max-bytes', '2'])).body.error, 'LIMIT_REACHED')
    setMode('timeout')
    const beforeTimeout = calls.length
    const timedOut = await run(['search', 'port:443', '--allow-operation', 'OP-003', '--query-credit-budget', '1', '--max-pages', '2', '--max-requests', '2'])
    assert.equal(timedOut.body.error, 'UPSTREAM_ERROR')
    assert.match(timedOut.body.message, /uncertain/)
    assert.equal(calls.length, beforeTimeout + 1)
  })
})
