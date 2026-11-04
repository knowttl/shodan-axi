import { execFileSync, spawn } from 'node:child_process'
import { createServer } from 'node:https'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createTestTls } from './tls-fixture.mjs'

export async function withInvestigation(check) {
  const root = await mkdtemp(join(tmpdir(), 'shodan-investigation-'))
  let server
  try {
    const packed = JSON.parse(execFileSync('npm', ['pack', '--ignore-scripts', '--pack-destination', root, '--json'], { encoding: 'utf8' }))
    execFileSync('npm', ['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--prefix', root, join(root, packed[0].filename)], { stdio: 'ignore' })
    const executable = join(root, 'node_modules', '.bin', 'shodan-axi')
    const { keyFile, certFile } = await createTestTls(root, 'IP:127.0.0.1')
    const calls = []
    let mode = 'normal'
    const alerts = new Map([['alert-a', { id: 'alert-a', name: 'Synthetic alert', filters: { ip: ['192.0.2.0/24'] }, triggers: {}, notifiers: [], expiration: null }]])
    const notifiers = new Map([['notifier-a', { id: 'notifier-a', provider: 'email', description: 'Synthetic', args: { to: 'person@example.test', token: 'private-value' } }]])
    const banner = (transport, timestamp) => ({ ip_str: '192.0.2.7', port: 443, transport, timestamp, data: 'synthetic banner fake-secret', location: { country_code: 'CA' }, ssl: { cert: { pubkey: { bits: 2048, type: 'rsa' } } } })
    const banners = [banner('tcp', '2026-01-01'), banner('udp', '2026-01-02'), { ...banner('tcp', '2026-01-03'), metadata: { truncated: ['http.html'] } }]
    server = createServer({ key: await readFile(keyFile), cert: await readFile(certFile) }, async (request, response) => {
      const url = new URL(request.url, 'https://127.0.0.1')
      calls.push({ method: request.method, path: url.pathname, query: Object.fromEntries(url.searchParams) })
      if (mode === 'denied') { response.writeHead(403); response.end('{"error":"denied"}'); return }
      if (mode === 'redirect') { response.writeHead(301, { location: 'https://invalid.example/' }); response.end(); return }
      if (mode === 'malformed') { response.end('{broken'); return }
      if (mode === 'timeout') { request.socket.destroy(); return }
      if (mode === 'bad-port') { response.end('[22,"443"]'); return }
      if (request.method !== 'GET') {
        const chunks = []
        for await (const chunk of request) chunks.push(chunk)
        const input = Buffer.concat(chunks).toString()
        calls.at(-1).body = input
        const match = /^\/shodan\/alert\/([^/]+)$/.exec(url.pathname)
        if (request.method === 'POST' && url.pathname === '/notifier') {
          const fields = Object.fromEntries(new URLSearchParams(input)); const created = { id: 'notifier-new', provider: fields.provider, description: fields.description, args: fields }
          notifiers.set(created.id, created); response.end(JSON.stringify({ id: created.id, success: true })); return
        }
        if (request.method === 'POST' && url.pathname === '/shodan/alert') {
          const body = JSON.parse(input); const created = { id: 'alert-new', ...body, triggers: {}, notifiers: [], expiration: body.expires === 0 ? null : new Date(Date.now() + body.expires * 1000).toISOString() }
          alerts.set(created.id, created)
          if (mode === 'lost-write' || mode === 'lost-create-alert') { request.socket.destroy(); return }
          response.end(JSON.stringify(created)); return
        }
        const notifierMutation = /^\/notifier\/([^/]+)$/.exec(url.pathname)
        if (notifierMutation && request.method === 'DELETE') { notifiers.delete(notifierMutation[1]); response.end('{"success":true}'); return }
        if (notifierMutation && request.method === 'PUT') {
          Object.assign(notifiers.get(notifierMutation[1]).args, Object.fromEntries(new URLSearchParams(input)))
          response.end(JSON.stringify({ id: notifierMutation[1], success: true })); return
        }
        if (match && request.method === 'DELETE') {
          alerts.delete(match[1])
          if (mode === 'lost-write') { request.socket.destroy(); return }
          response.end('{"success":true}'); return
        }
        if (match && request.method === 'POST') {
          Object.assign(alerts.get(match[1]), JSON.parse(input))
          response.end(JSON.stringify(alerts.get(match[1]))); return
        }
        const trigger = /^\/shodan\/alert\/([^/]+)\/trigger\/([^/]+)$/.exec(url.pathname)
        if (trigger) {
          if (request.method === 'PUT' && mode !== 'trigger-unverified') alerts.get(trigger[1]).triggers[trigger[2]] = {}
          else delete alerts.get(trigger[1]).triggers[trigger[2]]
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
          const alert = alerts.get(association[1])
          if (request.method === 'PUT') alert.notifiers.push(association[2])
          else alert.notifiers = alert.notifiers.filter(entry => entry !== association[2])
          response.end('{"success":true}'); return
        }
        response.end('{"success":true}'); return
      }
      const alertInfo = /^\/shodan\/alert\/([^/]+)\/info$/.exec(url.pathname)
      if (alertInfo) {
        const selected = alerts.get(alertInfo[1])
        if (!selected) { response.writeHead(404); response.end('{}'); return }
        const changes = {
          'alert-name-mismatch': { name: 'Different name' },
          'alert-expiration-mismatch': { expiration: '2000-01-01T00:00:00.000Z' },
          'alert-expiration-too-long': { expiration: new Date(Date.now() + 120000).toISOString() },
          'alert-expiration-missing': { expiration: undefined },
        }
        response.end(JSON.stringify({ ...selected, ...changes[mode] })); return
      }
      const notifierInfo = /^\/notifier\/([^/]+)$/.exec(url.pathname)
      if (notifierInfo && notifierInfo[1] !== 'provider') {
        const selected = notifiers.get(notifierInfo[1])
        if (!selected) { response.writeHead(404); response.end('{}'); return }
        const changes = {
          'notifier-provider-mismatch': { provider: 'Different provider' },
          'notifier-description-mismatch': { description: 'Different description' },
          'notifier-args-mismatch': { args: { to: 'other@example.test' } },
          'notifier-args-missing': { args: undefined },
        }
        response.end(JSON.stringify({ ...selected, ...changes[mode] })); return
      }
      if (['/shodan/host/192.0.2.8', '/shodan/host/2001%3Adb8%3A%3A8'].includes(url.pathname)) {
        response.writeHead(mode === 'domain-enrichment-denied' ? 403 : 404)
        response.end('{"error":"host unavailable"}')
        return
      }
      const page = url.searchParams.get('page')
      const values = {
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
      }
      if (mode === 'domain-unindexed' || mode === 'domain-enrichment-denied') values['/dns/domain/example.test'] = {
        domain: 'example.test', data: [{ type: 'A', value: '192.0.2.8' }, { type: 'AAAA', value: '2001:db8::8' }, { type: 'A', value: '192.0.2.7' }], more: false,
      }
      response.setHeader('content-type', 'application/json')
      const errorStatus = { 'trickle-404': 404, 'trickle-429': 429, 'trickle-503': 503 }[mode]
        ?? (mode === 'trickle-enrichment' && url.pathname.startsWith('/shodan/host/') ? 404 : undefined)
      if (mode === 'trickle' || errorStatus !== undefined) {
        calls.at(-1).responseClosed = new Promise(resolve => { response.on('close', () => { resolve(!response.writableFinished) }) })
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
      response.end(JSON.stringify(values[url.pathname]))
    })
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
    const origin = `https://127.0.0.1:${server.address().port}`
    const preload = join(root, 'routing.mjs')
    const timerPreload = join(root, 'timers.mjs')
    await writeFile(timerPreload, `if (process.env.TEST_SHORT_REQUEST_TIMEOUT) { const schedule = globalThis.setTimeout; globalThis.setTimeout = (callback, delay, ...args) => schedule(callback, delay === 30000 ? 1000 : delay, ...args) }\n`)
    await writeFile(preload, `import https from 'node:https'; import { syncBuiltinESMExports } from 'node:module';\nconst request = https.request; https.request = function (url, ...args) { if (!(url instanceof URL)) throw new Error('Unexpected destination'); const family = url.origin; if (![${JSON.stringify(origin)}, 'https://internetdb.shodan.io', 'https://apiv6.shodan.io', 'https://trends.shodan.io', 'https://exploits.shodan.io'].includes(family)) throw new Error('Unexpected destination'); const target = new URL(url); if (family !== ${JSON.stringify(origin)}) { target.hostname = '127.0.0.1'; target.port = ${JSON.stringify(String(server.address().port))}; if (family === 'https://apiv6.shodan.io') { if (args[0].family !== 6) throw new Error('IPv6 was not selected'); if (process.env.TEST_FAIL_V6) throw new Error('IPv6 unavailable'); args[0].family = 4; args[0].headers = { ...args[0].headers, 'x-test-family': 'ipv6' }; } } const outgoing = request.call(this, target, ...args); outgoing.on('error', error => process.stderr.write('Fake transport error: ' + (error.code ?? error.message) + '\\n')); if (process.env.TEST_EXPIRE_ON_PATH === target.pathname) outgoing.on('response', response => { response.on('end', () => { const expired = Date.now() + 30000; Date.now = () => expired }) }); return outgoing }; syncBuiltinESMExports();\n`)
    const config = join(root, 'config.json')
    await writeFile(config, JSON.stringify({ version: 1, defaultProfile: 'selected', profiles: { selected: { auth: 'api-key', origin, apiKey: { env: 'TEST_SHODAN_KEY' } } } }), { mode: 0o600 })
    const env = { PATH: process.env.PATH, HOME: root, SHODAN_AXI_CONFIG: config, TEST_SHODAN_KEY: 'fake-secret', NODE_OPTIONS: `--import=${preload} --import=${timerPreload}`, NODE_EXTRA_CA_CERTS: certFile }
    const run = (args, overrides = {}) => new Promise((resolve, reject) => {
      const child = spawn(executable, [...args, '--json'], { cwd: root, env: { ...env, ...overrides }, signal: AbortSignal.timeout(10000) })
      let stdout = ''; let stderr = ''
      child.stdout.setEncoding('utf8').on('data', chunk => { stdout += chunk })
      child.stderr.setEncoding('utf8').on('data', chunk => { stderr += chunk })
      child.on('error', reject)
      child.on('close', code => {
        const body = JSON.parse(stdout)
        resolve({ code, stdout, stderr, body })
      })
    })
    await check({ root, calls, run, setMode: value => { mode = value } })
  } finally {
    if (server) await new Promise(resolve => server.close(resolve))
    await rm(root, { recursive: true, force: true })
  }
}
