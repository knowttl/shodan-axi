import assert from 'node:assert/strict'
import { test } from 'node:test'
import { withInvestigation } from './investigation-fixture.mjs'

test('CLI preserves retry waits through account and investigation errors', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, setVendorFailure }) => {
    for (const [args, status, retry, code, wait] of [
      [['info'], 503, '60', 'UPSTREAM_ERROR', 60],
      [['ports'], 503, '60', 'UPSTREAM_ERROR', 60],
      [['search', 'port:443', '--allow-operation', 'OP-003', '--query-credit-budget', '1'], 503, '60', 'UPSTREAM_ERROR', 60],
      [['info'], 429, 'Wed, 01 Jan 2020 00:00:00 GMT', 'RATE_LIMITED', 0],
      [['query', 'list'], 429, 'Wed, 01 Jan 2020 00:00:00 GMT', 'RATE_LIMITED', 0],
    ]) {
      setVendorFailure({ status, headers: { 'Retry-After': retry }, reason: 'Temporarily unavailable fake-secret AccountKey=private' })
      const result = await run(args)
      assert.equal(result.code, 1)
      assert.equal(result.body.error, code)
      assert.equal(result.body.retryAfterSeconds, wait)
      assert.match(result.body.message, /127\.0\.0\.1.*Temporarily unavailable/)
      assert.doesNotMatch(result.stdout, /fake-secret|AccountKey=private/)
    }
  })
})

test('investigation translations preserve sanitized vendor details and retry waits', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, setVendorFailure }) => {
    const localHost = '127.0.0.1'
    const commands = [
      [['query', 'list'], localHost],
      [['query', 'search', 'TLS'], localHost],
      [['query', 'tags'], localHost],
      [['trends', 'port:443', '--allow-operation', 'OP-054', '--accept-unknown-cost', '--max-requests', '1', '--query-credit-budget', '1'], 'trends.shodan.io'],
      [['trends', 'filters'], 'trends.shodan.io'],
      [['trends', 'facets'], 'trends.shodan.io'],
      [['exploits', 'search', 'TLS', '--allow-operation', 'OP-057', '--accept-unknown-cost', '--max-requests', '1', '--query-credit-budget', '1'], 'exploits.shodan.io'],
      [['exploits', 'count', 'TLS', '--allow-operation', 'OP-058', '--accept-unknown-cost', '--max-requests', '1', '--query-credit-budget', '1'], 'exploits.shodan.io'],
    ]
    for (const [status, code] of [[301, 'REDIRECT_REFUSED'], [401, 'ACCESS_DENIED'], [403, 'ACCESS_DENIED']]) {
      setVendorFailure({ status, headers: { 'Retry-After': '60', location: 'https://invalid.example/' }, reason: 'Plan upgrade required fake-secret AccountKey=private' })
      for (const [args, hostname] of commands) {
        const result = await run(args)
        assert.equal(result.code, 1)
        assert.equal(result.body.error, code)
        assert.equal(result.body.retryAfterSeconds, 60)
        assert.equal(result.body.message, `Request to ${hostname} failed with HTTP ${status}: Plan upgrade required [REDACTED] AccountKey=[REDACTED]`)
        assert.doesNotMatch(result.stdout, /fake-secret|AccountKey=private/)
      }
    }
    setVendorFailure(undefined)
    assert.equal((await run(['query', 'list'])).code, 0)
  })
})
