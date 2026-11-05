import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import https from 'node:https'
import { syncBuiltinESMExports } from 'node:module'
import { test } from 'node:test'
import { requestJson } from '../dist/vendor.js'

function transport(t, statusCode) {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: 0 })
  const response = Object.assign(new EventEmitter(), { statusCode, headers: {}, destroy() {} })
  const request = Object.assign(new EventEmitter(), {
    destroyed: false,
    end() {},
    destroy(error) { this.destroyed = true; if (error) this.emit('error', error) },
  })
  let sendHeaders
  t.mock.method(https, 'request', (url, options, callback) => {
    sendHeaders = () => callback(response)
    return request
  })
  syncBuiltinESMExports()
  t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports() })
  return { request, response, sendHeaders: () => sendHeaders() }
}

for (const [status, code] of [[200, 'UPSTREAM_ERROR'], [404, 'NOT_FOUND'], [429, 'RATE_LIMITED'], [503, 'UPSTREAM_ERROR']]) {
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

for (const [status, body] of [[200, '[22,443]'], [503, '{"error":"Service unavailable"}']]) {
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
