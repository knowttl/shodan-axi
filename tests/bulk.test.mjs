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
    const result = await run(['data', 'download', 'raw-daily', 'synthetic.json'], { SHODAN_AXI_CONFIG: join(root, 'missing') })
    assert.equal(result.body.error, 'STORAGE_POLICY_UNAVAILABLE')
    assert.match(result.body.message, /host not yet determined/)
    assert.equal(calls.length, 0)
  })
})

test('synthetic dataset transfer verifies bytes after confirmation', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, calls, allowFixtureStorage }) => {
    await allowFixtureStorage()
    const destination = join(root, 'data.json')
    const args = ['data', 'download', 'raw-daily', 'synthetic.json', '--filename', destination, '--max-bytes', '10', '--max-requests', '2', '--allow-operation', 'OP-034,OP-035,OP-071']
    const preview = await run(args)
    assert.equal(preview.body.status, 'preview', preview.stdout)
    const result = await run([...args, '--execute', '--confirm', preview.body.token])
    assert.equal(result.body.complete, true, result.stdout)
    assert.equal(await readFile(destination, 'utf8'), 'abcdefghij')
    const fetch = calls.find(call => call.path === '/fixture')
    assert.equal(fetch.query.key, undefined)
    assert.doesNotMatch(result.stdout + preview.stdout, /private-signature/)
  })
})

test('search export requires confirmation and saves bounded gzip JSON lines', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, calls }) => {
    const destination = join(root, 'search.json.gz')
    const args = ['download', 'port:443', '--filename', destination, '--limit', '2', '--max-bytes', '10000', '--max-requests', '3', '--query-credit-budget', '1', '--allow-operation', 'OP-003']
    const preview = await run(args)
    assert.equal(preview.body.status, 'preview', preview.stdout)
    assert.equal(calls.filter(call => call.path === '/shodan/host/search').length, 0)
    const result = await run([...args, '--execute', '--confirm', preview.body.token])
    assert.equal(result.body.complete, true, result.stdout)
    assert.equal(gunzipSync(await readFile(destination)).toString().trim().split('\n').length, 2)
    assert.equal((await run([...args, '--execute', '--confirm', preview.body.token])).body.error, 'PLAN_NOT_FOUND')
  })
})

test('alert download previews normalized monitored networks before searching', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, calls, setMode }) => {
    setMode('alert-evidence')
    const destination = join(root, 'alerts.json.gz')
    const args = ['alert', 'download', '--filename', destination, '--limit', '2', '--max-bytes', '10000', '--max-requests', '4', '--query-credit-budget', '1', '--allow-operation', 'OP-003']
    const preview = await run(args)
    assert.equal(preview.body.status, 'preview', preview.stdout)
    assert.equal(preview.body.query, 'net:192.0.2.0/24')
    assert.equal(calls.filter(call => call.path === '/shodan/host/search').length, 0)
    const result = await run([...args, '--execute', '--confirm', preview.body.token])
    assert.equal(result.body.complete, true, result.stdout)
    assert.equal(gunzipSync(await readFile(destination)).toString().trim().split('\n').length, 2)
  })
})

test('resuming rejects a changed source before appending bytes', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, setMode, allowFixtureStorage }) => {
    await allowFixtureStorage(); setMode('dataset-interrupt')
    const destination = join(root, 'large.json')
    const args = ['data', 'download', 'raw-daily', 'synthetic.json', '--filename', destination, '--max-bytes', '1048586', '--max-requests', '3', '--allow-operation', 'OP-034,OP-035,OP-071']
    const preview = await run(args)
    const interrupted = await run([...args, '--execute', '--confirm', preview.body.token])
    assert.notEqual(interrupted.code, 0)
    const before = await readFile(`${destination}.partial`)
    assert.equal(before.length, 1024 * 1024)
    setMode('dataset-version-change')
    const resume = [...args, '--resume']
    const resumedPreview = await run(resume)
    const result = await run([...resume, '--execute', '--confirm', resumedPreview.body.token])
    assert.equal(result.body.error, 'SOURCE_CHANGED', result.stdout)
    assert.deepEqual(await readFile(`${destination}.partial`), before)
  })
})

test('a matching source resumes and verifies the complete dataset', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, setMode, allowFixtureStorage }) => {
    await allowFixtureStorage(); setMode('dataset-interrupt')
    const destination = join(root, 'resumed.json')
    const args = ['data', 'download', 'raw-daily', 'synthetic.json', '--filename', destination, '--max-bytes', '1048586', '--max-requests', '3', '--allow-operation', 'OP-034,OP-035,OP-071']
    const preview = await run(args)
    assert.notEqual((await run([...args, '--execute', '--confirm', preview.body.token])).code, 0)
    setMode('dataset-stable')
    const resume = [...args, '--resume']
    const resumedPreview = await run(resume)
    const result = await run([...resume, '--execute', '--confirm', resumedPreview.body.token])
    assert.equal(result.body.complete, true, result.stdout)
    assert.equal((await readFile(destination)).length, 1048586)
  })
})

test('dataset redirects are refused before any redirected request', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, calls, setMode, allowFixtureStorage }) => {
    await allowFixtureStorage(); setMode('dataset-redirect')
    const destination = join(root, 'redirect.json')
    const args = ['data', 'download', 'raw-daily', 'synthetic.json', '--filename', destination, '--max-bytes', '1048586', '--max-requests', '3', '--allow-operation', 'OP-034,OP-035,OP-071']
    const preview = await run(args)
    const result = await run([...args, '--execute', '--confirm', preview.body.token])
    assert.notEqual(result.code, 0)
    assert.equal(calls.some(call => call.path === '/private'), false)
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
