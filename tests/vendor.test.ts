import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import https from 'node:https'
import { syncBuiltinESMExports } from 'node:module'
import { test } from 'node:test'
import { requestJson } from '../dist/vendor.js'
import type { IncomingHttpHeaders } from 'node:http'
import type { TestContext } from 'node:test'

function transport(t: TestContext, statusCode: number) {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: 0 })
  const response = Object.assign(new EventEmitter(), { statusCode, headers: {} as IncomingHttpHeaders, destroy() {} })
  const request = Object.assign(new EventEmitter(), {
    destroyed: false,
    end() {},
    destroy(this: EventEmitter & { destroyed: boolean }, error?: Error) { this.destroyed = true; if (error) this.emit('error', error) },
  })
  let sendHeaders: () => void
  t.mock.method(https, 'request', (_url: URL, _options: https.RequestOptions, callback: (message: typeof response) => void) => {
    sendHeaders = () => callback(response)
    return request
  })
  syncBuiltinESMExports()
  t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports() })
  return { request, response, sendHeaders: () => sendHeaders() }
}

for (const [status, code] of [[200, 'UPSTREAM_ERROR'], [404, 'NOT_FOUND'], [429, 'RATE_LIMITED'], [503, 'UPSTREAM_ERROR']] satisfies [unknown, ...unknown[]][]) {
  test(`HTTP ${status} body collection keeps the original deadline`, async t => {
    const { request, sendHeaders } = transport(t, status)
    const result = requestJson('https://api.shodan.io', '/shodan/ports', undefined, {}, 1024, 500)
    const rejected = assert.rejects(result, { code })
    t.mock.timers.tick(400)
    sendHeaders()
    t.mock.timers.tick(99)
    assert.equal(request.destroyed, false)
    t.mock.timers.tick(1)
    assert.equal(request.destroyed, true)
    await rejected
  })
}

for (const [status, body] of [[200, '[22,443]'], [503, '{"error":"Service unavailable"}']] satisfies [unknown, ...unknown[]][]) {
  test(`HTTP ${status} body can complete within the remaining budget`, async t => {
    const { response, sendHeaders } = transport(t, status)
    const result = requestJson('https://api.shodan.io', '/shodan/ports', undefined, {}, 1024, 500)
    t.mock.timers.tick(400)
    sendHeaders()
    t.mock.timers.tick(99)
    response.emit('data', Buffer.from(body))
    response.emit('end')
    if (status === 200) assert.deepEqual(await result, [22, 443])
    else await assert.rejects(result, { code: 'UPSTREAM_ERROR', message: 'Request to api.shodan.io failed with HTTP 503: Service unavailable' })
  })
}

for (const status of [301, 401, 403, 404, 429, 503]) {
  for (const [retry, retryAfterSeconds] of [
    ['60', 60],
    ['Thu, 01 Jan 1970 00:01:00 GMT', 60],
    ['Wed, 31 Dec 1969 23:59:00 GMT', 0],
    ['not a date', undefined],
  ] satisfies [unknown, ...unknown[]][]) {
    test(`HTTP ${status} preserves Retry-After ${retry}`, async t => {
      const { response, sendHeaders } = transport(t, status)
      response.headers['retry-after'] = retry
      const result = requestJson('https://api.shodan.io', '/shodan/ports', undefined)
      t.mock.timers.tick(250)
      sendHeaders()
      response.emit('end')
      await assert.rejects(result, error => {
        assert.equal((error as { retryAfterSeconds?: number }).retryAfterSeconds, retryAfterSeconds)
        return true
      })
    })
  }
}
