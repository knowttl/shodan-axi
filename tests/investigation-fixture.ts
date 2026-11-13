import { execFileSync, spawn } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { createServer } from 'node:https'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createTestTls } from './tls-fixture.ts'
import type { ChildProcessWithoutNullStreams } from 'node:child_process'
import type { AddressInfo } from 'node:net'
import type { Duplex } from 'node:stream'

export type VendorCall = { method: string | undefined; path: string; query: Record<string, string>; body?: string; responseClosed?: Promise<boolean> }
type VendorFailure = { status: number; reason: string; headers: Record<string, string> }
type RunResult = { code: number | null; stdout: string; stderr: string; body: ReturnType<typeof JSON.parse> }
type Run = (args: readonly string[], overrides?: NodeJS.ProcessEnv, onChild?: (child: ChildProcessWithoutNullStreams) => void) => Promise<RunResult>
type Worker = {
  readsPath: string
  send: (value: unknown) => void
  sendRaw: (value: string | Buffer) => void
  next: () => Promise<ReturnType<typeof JSON.parse>>
  closed: Promise<number | null>
  close: () => void
}
type InvestigationFixture = {
  root: string
  calls: VendorCall[]
  run: Run
  runHosted: (args: readonly string[]) => Promise<RunResult>
  runInteractive: (args: readonly string[], input?: string) => Promise<{ code: number | null; stdout: string }>
  launchWorker: (options?: { admitted?: boolean; profilePath?: string; overrides?: NodeJS.ProcessEnv }) => Worker
  hostProfile: string
  config: string
  server: ReturnType<typeof createServer>
  certFile: string
  setMode: (value: string) => void
  setVendorFailure: (value: VendorFailure | undefined) => void
}
type Alert = { id: string; name: string; filters: { ip: string[] }; triggers: Record<string, unknown>; notifiers: string[]; expiration: string | null }
type Notifier = { id: string; provider: string; description: string | null | undefined; args: Record<string, string> }

export async function withInvestigation(check: (fixture: InvestigationFixture) => Promise<void>) {
  const root = await mkdtemp(join(tmpdir(), 'shodan-investigation-'))
  let server: ReturnType<typeof createServer> | undefined
  try {
    const packed = JSON.parse(execFileSync('npm', ['pack', '--ignore-scripts', '--pack-destination', root, '--json'], { encoding: 'utf8' }))
    execFileSync('npm', ['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--prefix', root, join(root, packed[0].filename)], { stdio: 'ignore' })
    const executable = join(root, 'node_modules', '.bin', 'shodan-axi')
    const { keyFile, certFile } = await createTestTls(root, 'IP:127.0.0.1')
    const calls: VendorCall[] = []
    let mode = 'normal'
    let vendorFailure: VendorFailure | undefined
    const inject = (value: unknown): unknown => {
      if (mode !== 'hosted-injection' || value === null || typeof value !== 'object') return value
      if (Array.isArray(value)) return value.map(inject)
      return { ...Object.fromEntries(Object.entries(value).map(([name, item]) => [name, inject(item)])), unknown_vendor: 'injected-private', access_token: 'injected-private' }
    }
    const alerts = new Map<string, Alert>([['alert-a', { id: 'alert-a', name: 'Synthetic alert', filters: { ip: ['192.0.2.0/24'] }, triggers: {}, notifiers: [], expiration: null }]])
    const notifiers = new Map<string, Notifier>([['notifier-a', { id: 'notifier-a', provider: 'email', description: null, args: { to: 'person@example.test', token: 'private-value' } }]])
    const organization = { id: 'org-a', name: 'Synthetic Org', admins: [{ username: 'owner', email: 'owner@example.test' }], members: [{ username: 'existing', email: 'existing@example.test' }, { username: 'other', email: 'other@example.test' }], domains: ['example.test'], logo: false, api_key: 'issued-secret' }
    const banner = (transport: string, timestamp: string) => ({ ip_str: '192.0.2.7', port: 443, transport, timestamp, data: 'synthetic banner fake-secret', location: { country_code: 'CA' }, ssl: { cert: { pubkey: { bits: 2048, type: 'rsa' } } } })
    const banners = [banner('tcp', '2026-01-01'), banner('udp', '2026-01-02'), { ...banner('tcp', '2026-01-03'), metadata: { truncated: ['http.html'] } }]
    server = createServer({ key: await readFile(keyFile), cert: await readFile(certFile) }, async (request, response) => {
      const url = new URL(request.url!, 'https://127.0.0.1')
      calls.push({ method: request.method, path: url.pathname, query: Object.fromEntries(url.searchParams) })
      if (vendorFailure) { response.writeHead(vendorFailure.status, vendorFailure.headers); response.end(JSON.stringify({ error: vendorFailure.reason })); return }
      if (mode.startsWith('scan-collect') && request.method === 'GET' && (url.pathname === '/shodan/alert/alert-new' || url.pathname === '/shodan/ports/443')) {
        const service = (id: string, ip: string, port: number, transport: string) => ({ _shodan: { id }, ip_str: ip, port, transport, timestamp: '2026-01-01', data: 'synthetic' })
        const first = service('banner-a', '192.0.2.7', 443, 'tcp')
        response.writeHead(200, { 'content-type': 'application/json' }); response.flushHeaders()
        response.end([first, service('banner-b', '192.0.2.7', 53, 'udp'), first, service('banner-other', '192.0.2.8', 80, 'tcp')].map(value => `${JSON.stringify(value)}\n`).join('')); return
      }
      if (mode.startsWith('stream') && (url.pathname.startsWith('/shodan/banners') || url.pathname.startsWith('/shodan/asn/') || url.pathname.startsWith('/shodan/countries/') || url.pathname.startsWith('/shodan/ports/') || url.pathname.startsWith('/shodan/vulns/') || url.pathname === '/shodan/custom' || url.pathname === '/shodan/alert' || url.pathname.startsWith('/shodan/alert/') || url.pathname.startsWith('/shodan/tags/') || url.pathname.startsWith('/threatnet/'))) {
        if (mode === 'stream-denied') { response.writeHead(403); response.end(); return }
        if (mode === 'stream-rate-limited') { response.writeHead(429); response.end(); return }
        if (mode === 'stream-connection-error') { request.socket.destroy(); return }
        if (mode === 'stream-no-headers') return
        if (mode === 'stream-idle') { response.write('\n'); return }
        if (mode === 'stream-partial') { response.end('{"ip_str":"192.0.2.'); return }
        if (mode === 'stream-malformed') { response.end('{"bad":true}\n'); return }
        const threat = url.pathname.startsWith('/threatnet/')
        const first = threat ? { synthetic_sequence: 1, text: 'Café', ...(mode === 'stream-secrets' ? { nested: { api_key: 'synthetic-private', note: 'AccountKey=synthetic-private', pem: '-----BEGIN CERTIFICATE-----\nsynthetic\n-----END CERTIFICATE-----', jwt: 'eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.signature', sas: 'https://example.test/?sig=synthetic' } } : {}) } : { ip_str: '192.0.2.7', port: 443, transport: 'tcp', timestamp: '2026-01-01', data: mode === 'stream-secrets' ? 'AccountKey=synthetic-private' : 'Café', ...(mode === 'stream-secrets' ? { api_key: 'synthetic-private', arbitrary: 'private' } : {}), ...(mode === 'stream-radar' ? { location: { latitude: 49.28, longitude: -123.12 } } : {}) }
        const second = threat ? { synthetic_sequence: 2, text: 'second' } : { ip_str: '192.0.2.8', port: 443, transport: 'tcp', timestamp: '2026-01-02', data: 'second', ...(mode === 'stream-radar' ? { location: { latitude: 49.29, longitude: -123.13 } } : {}) }
        const sse = mode.startsWith('stream-sse')
        response.setHeader('content-type', sse ? 'text/event-stream' : 'application/json')
        const frame = (value: unknown) => sse ? `data: ${JSON.stringify(value)}\n\n` : `${JSON.stringify(value)}\n`
        if (mode.endsWith('-byte-cut')) { response.end(`${frame(first)}${frame(second)}${frame({ ...first, data: 'x'.repeat(600) })}`); return }
        if (mode.includes('-invalid-')) {
          const suffix = mode.endsWith('-json') ? '{broken}\n' : mode.endsWith('-schema') ? '[]\n' : mode.endsWith('-utf8-eof') ? Buffer.from([0xc3]) : Buffer.from([0xff, 10])
          response.end(Buffer.concat([Buffer.from(`${frame(first)}${frame({ event: 'debug', discarded: 3 })}`), Buffer.isBuffer(suffix) ? suffix : Buffer.from(sse ? `data: ${suffix}\n` : suffix)])); return
        }
        if (mode === 'stream-wait') { response.write(frame(first)); return }
        if (mode === 'stream-wait-accounting') { response.write(`${frame(first)}${frame({ event: 'debug', discarded: 3 })}{"ip_str":`); return }
        const payload = Buffer.from(`\n${frame(first)}${frame({ event: 'debug', discarded: 3 })}${frame(second)}`)
        const split = payload.indexOf(Buffer.from('é')) + 1
        response.write(payload.subarray(0, split))
        setImmediate(() => { response.end(payload.subarray(split)) })
        return
      }
      if (mode === 'scan-poll-failure' && url.pathname === '/shodan/scan/scan-a' && calls.filter(call => call.path === url.pathname).length > 1) { response.writeHead(503); response.end('{}'); return }
      if (mode === 'denied') { response.writeHead(403); response.end('{"error":"denied"}'); return }
      if (mode === 'redirect') { response.writeHead(301, { location: 'https://invalid.example/' }); response.end(); return }
      if (mode === 'malformed') { response.end('{broken'); return }
      if (mode === 'timeout') { request.socket.destroy(); return }
      if (mode === 'bad-port') { response.end('[22,"443"]'); return }
      if (mode === 'probe-lost' && url.pathname.startsWith('/api/geo')) { request.socket.destroy(); return }
      if (request.method !== 'GET') {
        const chunks = []
        for await (const chunk of request) chunks.push(chunk)
        const input = Buffer.concat(chunks).toString()
        calls.at(-1)!.body = input
        if (request.method === 'POST' && ['/shodan/scan', '/shodan/scan/internet'].includes(url.pathname)) {
          if (mode === 'lost-write') { request.socket.destroy(); return }
          if (mode === 'scan-rejected') { response.end('{"id":"scan-a","count":2,"credits_left":98,"error":"rejected"}'); return }
          response.end(url.pathname === '/shodan/scan' ? mode.startsWith('scan-collect') ? '{"id":"scan-a","count":1,"credits_left":98}' : '{"id":"scan-a","count":2,"credits_left":98}' : '{"id":"scan-internet"}'); return
        }
        const orgMember = /^\/org\/member\/([^/]+)$/.exec(url.pathname)
        if (orgMember) {
          const email = decodeURIComponent(orgMember[1]!)
          if (mode !== 'org-unchanged') {
            if (request.method === 'PUT') organization.members.push({ username: 'new', email })
            else organization.members = organization.members.filter(member => member.email !== email)
          }
          if (mode === 'lost-write') { request.socket.destroy(); return }
          response.end('{"success":true,"api_key":"issued-secret"}'); return
        }
        const match = /^\/shodan\/alert\/([^/]+)$/.exec(url.pathname)
        if (request.method === 'POST' && url.pathname === '/notifier') {
          const fields = Object.fromEntries(new URLSearchParams(input)); const created = { id: 'notifier-new', provider: fields.provider!, description: fields.description, args: fields }
          notifiers.set(created.id, created); response.end(JSON.stringify({ id: created.id, success: true })); return
        }
        if (request.method === 'POST' && url.pathname === '/shodan/alert') {
          const body = JSON.parse(input); const created = { id: 'alert-new', ...body, triggers: {}, notifiers: [], expiration: body.expires === 0 ? null : new Date(Date.now() + body.expires * 1000).toISOString() }
          alerts.set(created.id, created)
          if (mode === 'lost-write' || mode === 'lost-create-alert') { request.socket.destroy(); return }
          response.end(JSON.stringify(created)); return
        }
        const notifierMutation = /^\/notifier\/([^/]+)$/.exec(url.pathname)
        if (notifierMutation && request.method === 'DELETE') { notifiers.delete(notifierMutation[1]!); response.end('{"success":true}'); return }
        if (notifierMutation && request.method === 'PUT') {
          Object.assign(notifiers.get(notifierMutation[1]!)!.args, Object.fromEntries(new URLSearchParams(input)))
          response.end(JSON.stringify({ id: notifierMutation[1]!, success: true })); return
        }
        if (match && request.method === 'DELETE') {
          if (mode === 'scan-collect-cleanup-failed') { response.writeHead(500); response.end('{}'); return }
          alerts.delete(match[1]!)
          if (mode === 'lost-write') { request.socket.destroy(); return }
          response.end('{"success":true}'); return
        }
        if (match && request.method === 'POST') {
          Object.assign(alerts.get(match[1]!)!, JSON.parse(input))
          response.end(JSON.stringify(alerts.get(match[1]!)!)); return
        }
        const trigger = /^\/shodan\/alert\/([^/]+)\/trigger\/([^/]+)$/.exec(url.pathname)
        if (trigger) {
          if (request.method === 'PUT' && mode !== 'trigger-unverified') alerts.get(trigger[1]!)!.triggers[trigger[2]!] = {}
          else delete alerts.get(trigger[1]!)!.triggers[trigger[2]!]
          response.end('{"success":true}'); return
        }
        const ignore = /^\/shodan\/alert\/([^/]+)\/trigger\/([^/]+)\/ignore\/([^/]+)(?:\/([^/]+))?$/.exec(url.pathname)
        if (ignore) {
          if (mode === 'ignore-timeout') return
          if (mode === 'ignore-failed') { response.writeHead(500); response.end('{"error":"failed"}'); return }
          if (mode === 'ignore-rejected') { response.end('{"success":false}'); return }
          if (mode === 'ignore-ambiguous') { response.end('{}'); return }
          if (mode === 'ignore-malformed') { response.end('{broken'); return }
          response.end('{"success":true}'); return
        }
        const association = /^\/shodan\/alert\/([^/]+)\/notifier\/([^/]+)$/.exec(url.pathname)
        if (association) {
          const alert = alerts.get(association[1]!)!
          if (request.method === 'PUT') alert.notifiers.push(association[2]!)
          else alert.notifiers = alert.notifiers.filter(entry => entry !== association[2]!)
          response.end('{"success":true}'); return
        }
        response.end('{"success":true}'); return
      }
      const alertInfo = /^\/shodan\/alert\/([^/]+)\/info$/.exec(url.pathname)
      if (alertInfo) {
        const selected = alerts.get(alertInfo[1]!)
        if (!selected) { response.writeHead(404); response.end('{}'); return }
        const changes: Record<string, Record<string, unknown>> = {
          'alert-name-mismatch': { name: 'Different name' },
          'alert-expiration-mismatch': { expiration: '2000-01-01T00:00:00.000Z' },
          'alert-expiration-too-long': { expiration: new Date(Date.now() + 120000).toISOString() },
          'alert-expiration-missing': { expiration: undefined },
        }
        response.end(JSON.stringify(inject({ ...selected, ...changes[mode] }))); return
      }
      const notifierInfo = /^\/notifier\/([^/]+)$/.exec(url.pathname)
      if (notifierInfo && notifierInfo[1]! !== 'provider') {
        const selected = notifiers.get(notifierInfo[1]!)
        if (!selected) { response.writeHead(404); response.end('{}'); return }
        const changes: Record<string, Record<string, unknown>> = {
          'notifier-provider-mismatch': { provider: 'Different provider' },
          'notifier-description-mismatch': { description: 'Different description' },
          'notifier-args-mismatch': { args: { to: 'other@example.test' } },
          'notifier-args-missing': { args: undefined },
        }
        response.end(JSON.stringify(inject({ ...selected, ...changes[mode] }))); return
      }
      if (['/shodan/host/192.0.2.8', '/shodan/host/2001%3Adb8%3A%3A8'].includes(url.pathname)) {
        response.writeHead(mode === 'domain-enrichment-denied' ? 403 : 404)
        response.end('{"error":"host unavailable"}')
        return
      }
      const page = url.searchParams.get('page')
      const values: Record<string, unknown> = {
        '/api-info': { query_credits: 20, scan_credits: 98 },
        '/shodan/data': [{ name: 'raw-daily', description: 'Synthetic daily banners', scope: 'daily' }],
        '/shodan/data/raw-daily': [{ name: 'synthetic.json', size: 10, sha1: 'd68c19a0a345b7eab78d5e11e991c026ec60db63', timestamp: 1793707200000, url: `https://127.0.0.1:${(server!.address() as AddressInfo).port}/fixture?signature=private-signature` }],
        '/shodan/host/192.0.2.7': { ip_str: '192.0.2.7', ports: [443], ...(url.searchParams.get('minify') === 'true' || mode === 'missing-banners' ? {} : { data: mode === 'placeholder' ? [...banners, { ...banner('tcp', '2026-01-04'), placeholder: true }] : banners }) },
        '/shodan/host/count': { total: 2, facets: { [url.searchParams.get('facets')?.split(':')[0] ?? 'port']: [{ value: 443, count: 1 }, { value: 80, count: 1 }] } },
        '/shodan/host/search': { total: mode === 'empty' ? 0 : mode === 'later-page' ? 102 : 2, matches: mode === 'empty' ? [] : mode === 'long' ? [{ ...banners[0], data: 'x'.repeat(600) }] : mode === 'multipage' ? (page === '2' ? banners.slice(1, 2) : banners.slice(0, 1)) : mode === 'later-page' ? (page === '1' ? Array.from({ length: 100 }, () => banners[0]) : page === '2' ? banners.slice(0, 2) : []) : page === '2' ? [] : banners.slice(0, 2) },
        '/shodan/host/search/facets': ['port', 'country'], '/shodan/host/search/filters': ['asn', 'port'],
        '/shodan/host/search/tokens': { attributes: { ports: [443] }, errors: [], string: '', filters: ['port'] }, '/shodan/ports': [22, 443],
        '/dns/domain/example.test': { domain: 'example.test', data: mode === 'domain-empty-terminal' ? [] : mode === 'domain-many' ? [{ type: 'A', value: '192.0.2.7' }, { type: 'A', value: '192.0.2.8' }] : mode === 'domain-txt' || mode === 'domain-terminal' ? [{ type: 'A', value: '192.0.2.7' }, { type: 'TXT', value: '192.0.2.9' }] : [{ type: 'A', value: '192.0.2.7' }], more: mode !== 'domain-terminal' && mode !== 'domain-empty-terminal' },
        '/dns/resolve': { 'example.test': '192.0.2.7', 'monkey.example': '192.0.2.7', 'missing.example.test': null }, '/dns/reverse': { '192.0.2.7': ['example.test'], '192.0.2.8': [] },
        '/tools/httpheaders': { 'User-Agent': 'synthetic', Authorization: 'Bearer other-credential', 'Proxy-Authorization': 'Basic proxy-credential' },
        '/tools/myip': request.headers['x-test-family'] === 'ipv6' ? '2001:db8::7' : '192.0.2.7',
        '/192.0.2.7': { ip: '192.0.2.7', ports: [443], cpes: [], hostnames: [], tags: [], vulns: ['CVE-2020-0001'] },
        '/labs/honeyscore/192.0.2.7': 0.25, '/shodan/services': { 443: 'https' },
        '/shodan/query': { total: 11, matches: [{ title: 'Synthetic TLS', query: 'port:443', votes: 3 }] },
        '/shodan/query/search': { total: 1, matches: [{ title: 'Synthetic TLS', query: 'port:443' }] },
        '/shodan/query/tags': { total: 2, matches: [{ value: 'test', count: 3 }, { value: 'tls', count: 2 }].slice(0, Number(url.searchParams.get('size') ?? 10)) },
        '/api/v1/search': { total: 7, matches: [{ month: '2026-09', count: 3 }, { month: '2026-10', count: 4 }], facets: { country: [{ key: '2026-10', values: [{ value: 'CA', count: 4 }] }, { key: '2026-09', values: [{ value: 'US', count: 3 }] }] } },
        '/api/v1/search/filters': ['all', 'asn', 'has_ipv6'], '/api/v1/search/facets': ['asn', 'country', 'vuln.verified'],
        '/api/search': { total: 1, matches: [{ _id: '2020-0001', source: 'CVE', cve: 'CVE-2020-0001', description: 'x'.repeat(600) }], facets: { source: [{ value: 'CVE', count: 1 }] } },
        '/api/count': { total: 1, facets: { source: [{ value: 'CVE', count: 1 }] } },
        '/shodan/alert/alert-a/info': { id: 'alert-a', name: 'Synthetic alert', filters: { ip: ['192.0.2.0/24'] }, triggers: {}, notifiers: [], expiration: null },
        '/shodan/alert/info': [...alerts.values()],
        '/shodan/alert/triggers': [{ name: 'any', rule: '*', description: 'Any service' }],
        '/notifier': { matches: [...notifiers.values()], total: notifiers.size },
        '/notifier/provider': { email: { required: ['to'] }, telegram: { required: ['chat_id', 'token'] } },
        '/notifier/notifier-a': { id: 'notifier-a', provider: 'email', description: 'Synthetic', args: { to: 'person@example.test', token: 'private-value' } },
        '/org': organization,
        '/shodan/protocols': { https: 'Synthetic HTTPS module' },
        '/shodan/scans': { matches: [{ id: 'scan-a', status: 'PROCESSING', created: '2026-01-01', status_check: '2026-01-02', credits_left: 98, size: 2, api_key: 'issued-secret', access_token: 'private-token', unknown: { nested: 'private-value' } }], total: 2, unknown: 'private-envelope', password: 'private-password' },
        '/shodan/scan/scan-a': { id: 'scan-a', status: 'PROCESSING', count: 2, created: '2026-01-01', api_key: 'issued-secret', access_token: 'private-token', unknown: { nested: 'private-value' } },
        '/api/ping/192.0.2.7': { ip: '192.0.2.7', is_alive: true, min_rtt: 5, avg_rtt: 6, max_rtt: 7, rtts: [5, 6, 7], packets_sent: 3, packets_received: 3, packet_loss: 0, from_loc: { city: 'West', country: 'CA', latlon: '49,-123' } },
        '/api/geoping/192.0.2.7': [{ ip: '192.0.2.7', is_alive: true, min_rtt: 5, avg_rtt: 6, max_rtt: 7, rtts: [5, 6, 7], packets_sent: 3, packets_received: 3, packet_loss: 0, from_loc: { city: 'West', country: 'CA', latlon: '49,-123' } }, { ip: '192.0.2.7', is_alive: false, min_rtt: 0, avg_rtt: 0, max_rtt: 0, rtts: [], packets_sent: 3, packets_received: 0, packet_loss: 1, from_loc: { city: 'East', country: 'CA', latlon: '43,-79' } }],
        '/api/dns/service.example.test': { answers: [{ type: 'A', value: '192.0.2.7' }], from_loc: { city: 'West', country: 'CA', latlon: '49,-123' } },
        '/api/geodns/service.example.test': [{ answers: [{ type: 'A', value: '192.0.2.7' }], from_loc: { city: 'West', country: 'CA', latlon: '49,-123' } }, { answers: [], from_loc: { city: 'East', country: 'CA', latlon: '43,-79' } }],
      }
      if (mode === 'alert-evidence') {
        values['/shodan/alert/info'] = [
          { id: 'alert-a', name: 'First', filters: { ip: ['192.0.2.0/24', '192.0.2.0/25'] }, triggers: { any: { ignore: [{ ip: '192.0.2.9', port: 80 }] } }, notifiers: [{ id: 'n1', provider: 'email', args: { token: 'private-notifier-secret' } }] },
          { id: 'alert-b', name: 'Second', filters: { ip: ['192.0.2.9/32'] }, triggers: {}, notifiers: [] },
        ]
      }
      if (mode === 'alert-expiration') {
        values['/shodan/alert/info'] = [
          { id: 'old', name: 'Old', filters: { ip: ['192.0.2.0/24'] }, expiration: '2000-01-01T00:00:00Z' },
          { id: 'current', name: 'Current', filters: { ip: ['192.0.2.0/24'] }, expiration: '2099-01-01T00:00:00Z' },
          { id: 'permanent', name: 'Permanent', filters: { ip: ['192.0.2.0/24'] }, expiration: null },
        ]
      }
      if (mode === 'alert-export-networks') {
        values['/shodan/alert/info'] = [{ id: 'alert-a', filters: { ip: ['192.0.2.0/24', '198.51.100.0/24'] } }]
      }
      if (mode === 'export-truncated') {
        values['/shodan/host/count'] = { total: 1 }
        values['/shodan/host/search'] = { total: 1, matches: [banners[2]] }
      }
      if (mode === 'alert-formula-facets') values['/shodan/host/count'] = { total: 1, facets: { domain: [{ value: '=1+2', count: 1 }] } }
      if (mode === 'alert-multiple-facets') values['/shodan/host/count'] = { total: 2, facets: { port: [{ value: 443, count: 2 }, { value: 80, count: 1 }], country: [{ value: 'CA', count: 2 }] } }
      if (mode === 'export-count-changed') values['/shodan/host/count'] = { total: 3 }
      if (mode === 'export-credits-changed') values['/api-info'] = { query_credits: 19 }
      if (mode === 'alert-top-buckets') {
        values['/shodan/alert/info'] = [{ id: 'one', name: 'One', filters: { ip: ['192.0.2.0/24', '192.0.2.0/25'] } }, { id: 'two', name: 'Two', filters: { ip: ['198.51.100.0/24'] } }]
        values['/shodan/host/count'] = url.searchParams.get('query') === 'net:192.0.2.0/24' ? { total: 10, facets: { port: [{ value: 443, count: 6 }] } } : { total: 8, facets: { port: [{ value: 80, count: 5 }] } }
      }
      if (mode === 'domain-unindexed' || mode === 'domain-enrichment-denied') values['/dns/domain/example.test'] = {
        domain: 'example.test', data: [{ type: 'A', value: '192.0.2.8' }, { type: 'AAAA', value: '2001:db8::8' }, { type: 'A', value: '192.0.2.7' }], more: false,
      }
      if (mode === 'bad-protocol') (values['/shodan/protocols'] as Record<string, unknown>).https = { description: 'invalid' }
      response.setHeader('content-type', 'application/json')
      const errorStatus = ({ 'trickle-404': 404, 'trickle-429': 429, 'trickle-503': 503 } as Record<string, number>)[mode]
        ?? (mode === 'trickle-enrichment' && url.pathname.startsWith('/shodan/host/') ? 404 : undefined)
      if (mode === 'trickle' || errorStatus !== undefined) {
        calls.at(-1)!.responseClosed = new Promise(resolve => { response.on('close', () => { resolve(!response.writableFinished) }) })
        response.writeHead(errorStatus ?? 200)
        response.write(' ')
        let chunks = 0
        const timer = setInterval(() => {
          response.write(' ')
          if (++chunks === 20) { clearInterval(timer); response.end(JSON.stringify(values[url.pathname])) }
        }, 100)
        response.on('close', () => { clearInterval(timer) })
        return
      }
      response.end(JSON.stringify(inject(values[url.pathname])))
    })
    await new Promise<void>(resolve => server!.listen(0, '127.0.0.1', resolve))
    const origin = `https://127.0.0.1:${(server.address() as AddressInfo).port}`
    const preload = join(root, 'routing.mjs')
    const timerPreload = join(root, 'timers.mjs')
    await writeFile(timerPreload, `if (process.env.TEST_SHORT_REQUEST_TIMEOUT) { const schedule = globalThis.setTimeout; globalThis.setTimeout = (callback, delay, ...args) => schedule(callback, delay === 30000 ? 1000 : delay, ...args) }\n`)
    await writeFile(preload, `import https from 'node:https'; import { syncBuiltinESMExports } from 'node:module';\nconst request = https.request; https.request = function (url, ...args) { if (!(url instanceof URL)) throw new Error('Unexpected destination'); const family = url.origin; if (![${JSON.stringify(origin)}, 'https://internetdb.shodan.io', 'https://apiv6.shodan.io', 'https://trends.shodan.io', 'https://exploits.shodan.io', 'https://geonet.shodan.io', 'https://stream.shodan.io'].includes(family)) throw new Error('Unexpected destination'); const target = new URL(url); if (family !== ${JSON.stringify(origin)}) { target.hostname = '127.0.0.1'; target.port = ${JSON.stringify(String((server.address() as AddressInfo).port))}; if (family === 'https://apiv6.shodan.io') { if (args[0].family !== 6) throw new Error('IPv6 was not selected'); if (process.env.TEST_FAIL_V6) throw new Error('IPv6 unavailable'); args[0].family = 4; args[0].headers = { ...args[0].headers, 'x-test-family': 'ipv6' }; } } const outgoing = request.call(this, target, ...args); outgoing.on('error', error => process.stderr.write('Fake transport error: ' + (error.code ?? error.message) + '\\n')); if (process.env.TEST_EXPIRE_ON_PATH === target.pathname) outgoing.on('response', response => { response.on('end', () => { const expired = Date.now() + 30000; Date.now = () => expired }) }); return outgoing }; syncBuiltinESMExports();\n`)
    const config = join(root, 'config.json')
    await writeFile(config, JSON.stringify({ version: 1, defaultProfile: 'selected', profiles: { selected: { auth: 'api-key', origin, apiKey: { env: 'TEST_SHODAN_KEY' } } } }), { mode: 0o600 })
    const hostProfile = join(root, 'host-profile.json')
    await writeFile(hostProfile, JSON.stringify({ version: 1, defaultProfile: 'artium', profiles: { artium: { auth: 'api-key', origin, apiKey: { env: 'ARTIUM_SECRET_0' } } } }), { mode: 0o600 })
    const tracePreload = join(root, 'trace-credentials.mjs')
    await writeFile(tracePreload, `import fs from 'node:fs'; import { syncBuiltinESMExports } from 'node:module'; const open = fs.promises.open; fs.promises.open = async function (path, ...args) { if ([${JSON.stringify(config)}, ${JSON.stringify(hostProfile)}].includes(path)) fs.appendFileSync(process.env.TEST_CREDENTIAL_READS, JSON.stringify(path) + '\\n'); return open.call(this, path, ...args) }; syncBuiltinESMExports();\n`)
    const env = { PATH: process.env.PATH, HOME: root, SHODAN_AXI_CONFIG: config, TEST_SHODAN_KEY: 'fake-secret', NODE_OPTIONS: `--import=${preload} --import=${timerPreload}`, NODE_EXTRA_CA_CERTS: certFile }
    const run: Run = (args, overrides = {}, onChild = () => {}) => new Promise((resolve, reject) => {
      const child = spawn(executable, [...args, '--json'], { cwd: root, env: { ...env, ...overrides }, signal: AbortSignal.timeout(10000) })
      onChild(child)
      let stdout = ''; let stderr = ''
      child.stdout.setEncoding('utf8').on('data', chunk => { stdout += chunk })
      child.stderr.setEncoding('utf8').on('data', chunk => { stderr += chunk })
      child.on('error', reject)
      child.on('close', code => {
        const lines = stdout.trim().split('\n')
        const body = JSON.parse(lines.at(-1)!)
        resolve({ code, stdout, stderr, body })
      })
    })
    const runInteractive = (args: readonly string[], input = 'q') => new Promise<{ code: number | null; stdout: string }>((resolve, reject) => {
      const quote = (text: string) => `'${text.replaceAll("'", "'\\''")}'`
      const child = spawn('script', ['-q', '-c', `stty rows 24 cols 80 && exec ${[executable, ...args].map(quote).join(' ')}`, '/dev/null'], { cwd: root, env, signal: AbortSignal.timeout(10000) })
      let stdout = ''; let sent = false
      child.stdout.setEncoding('utf8').on('data', chunk => {
        stdout += chunk
        if (!sent && stdout.includes('Press q to stop')) { sent = true; child.stdin.write(input) }
      })
      child.on('error', reject)
      child.on('close', code => { resolve({ code, stdout }) })
    })
    const admissionBinding = 'synthetic-host-admission-binding-01'
    const runHosted = (args: readonly string[]) => run([...args, '--config', hostProfile, '--profile', 'artium'], { ARTIUM_SECRET_0: 'fake-secret' })
    const launchWorker: InvestigationFixture['launchWorker'] = ({ admitted = true, profilePath = hostProfile, overrides = {} } = {}) => {
      const worker = join(root, 'node_modules/@knowttl/shodan-axi/bin/shodan-stream-worker.js')
      const readsPath = join(root, `credential-reads-${randomUUID()}.jsonl`)
      const workerEnv = { PATH: env.PATH, HOME: root, NODE_OPTIONS: `${env.NODE_OPTIONS} --import=${tracePreload}`, NODE_EXTRA_CA_CERTS: certFile, ARTIUM_SECRET_0: 'fake-secret', TEST_CREDENTIAL_READS: readsPath, ...overrides }
      const child = spawn(process.execPath, [worker], { cwd: root, env: workerEnv, stdio: ['ignore', 'pipe', 'pipe', 'pipe'], signal: AbortSignal.timeout(10000) })
      const channel = child.stdio[3] as Duplex; let pending = ''; const values: ReturnType<typeof JSON.parse>[] = []; const waiting: ((value: ReturnType<typeof JSON.parse>) => void)[] = []
      channel.setEncoding('utf8').on('data', chunk => {
        pending += chunk
        for (;;) {
          const end = pending.indexOf('\n'); if (end < 0) break
          const value = JSON.parse(pending.slice(0, end)); pending = pending.slice(end + 1)
          const resolve = waiting.shift(); if (resolve) resolve(value); else values.push(value)
        }
      })
      if (admitted) channel.write(`${JSON.stringify({ version: 1, type: 'admit', requestId: 'admit-1', admission: admissionBinding, profilePath })}\n`)
      return {
        readsPath,
        send: value => { channel.write(`${JSON.stringify(value)}\n`) },
        sendRaw: value => { channel.write(value) },
        next: () => values.length ? Promise.resolve(values.shift()) : new Promise(resolve => waiting.push(resolve)),
        closed: new Promise<number | null>((resolve, reject) => { child.on('error', reject); child.on('close', resolve) }),
        close: () => { channel.end() },
      }
    }
    await check({ root, calls, run, runHosted, runInteractive, launchWorker, hostProfile, config, server, certFile, setMode: value => { mode = value }, setVendorFailure: value => { vendorFailure = value } })
  } finally {
    if (server) await new Promise<Error | undefined>(resolve => server!.close(resolve))
    await rm(root, { recursive: true, force: true })
  }
}
