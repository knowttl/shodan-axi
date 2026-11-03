import { execFileSync, spawn } from 'node:child_process'
import { createServer } from 'node:https'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

export async function withInvestigation(check) {
  const root = await mkdtemp(join(tmpdir(), 'shodan-investigation-'))
  let server
  try {
    const packed = JSON.parse(execFileSync('npm', ['pack', '--ignore-scripts', '--pack-destination', root, '--json'], { encoding: 'utf8' }))
    execFileSync('npm', ['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--prefix', root, join(root, packed[0].filename)], { stdio: 'ignore' })
    const executable = join(root, 'node_modules', '.bin', 'shodan-axi')
    const keyFile = join(root, 'key.pem'); const certFile = join(root, 'cert.pem')
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyFile, '-out', certFile,
      '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'], { stdio: 'ignore' })
    const calls = []
    let mode = 'normal'
    const banner = (transport, timestamp) => ({ ip_str: '192.0.2.7', port: 443, transport, timestamp, data: 'synthetic banner fake-secret', location: { country_code: 'CA' }, ssl: { cert: { pubkey: { bits: 2048, type: 'rsa' } } } })
    const banners = [banner('tcp', '2026-01-01'), banner('udp', '2026-01-02'), { ...banner('tcp', '2026-01-03'), metadata: { truncated: ['http.html'] } }]
    server = createServer({ key: await readFile(keyFile), cert: await readFile(certFile) }, (request, response) => {
      const url = new URL(request.url, 'https://127.0.0.1')
      calls.push({ path: url.pathname, query: Object.fromEntries(url.searchParams) })
      if (mode === 'denied') { response.writeHead(403); response.end('{"error":"denied"}'); return }
      if (mode === 'malformed') { response.end('{broken'); return }
      if (mode === 'timeout') { request.socket.destroy(); return }
      if (mode === 'bad-port') { response.end('[22,"443"]'); return }
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
      }
      if (mode === 'domain-unindexed' || mode === 'domain-enrichment-denied') values['/dns/domain/example.test'] = {
        domain: 'example.test', data: [{ type: 'A', value: '192.0.2.8' }, { type: 'AAAA', value: '2001:db8::8' }, { type: 'A', value: '192.0.2.7' }], more: false,
      }
      response.setHeader('content-type', 'application/json')
      response.end(JSON.stringify(values[url.pathname]))
    })
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
    const origin = `https://127.0.0.1:${server.address().port}`
    const preload = join(root, 'routing.mjs')
    await writeFile(preload, `import https from 'node:https'; import { syncBuiltinESMExports } from 'node:module';\nconst request = https.request; https.request = function (url, ...args) { if (!(url instanceof URL)) throw new Error('Unexpected destination'); const family = url.origin; if (![${JSON.stringify(origin)}, 'https://internetdb.shodan.io', 'https://apiv6.shodan.io'].includes(family)) throw new Error('Unexpected destination'); const target = new URL(url); if (family !== ${JSON.stringify(origin)}) { target.hostname = '127.0.0.1'; target.port = ${JSON.stringify(String(server.address().port))}; if (family === 'https://apiv6.shodan.io') { if (args[0].family !== 6) throw new Error('IPv6 was not selected'); if (process.env.TEST_FAIL_V6) throw new Error('IPv6 unavailable'); args[0].family = 4; args[0].headers = { ...args[0].headers, 'x-test-family': 'ipv6' }; } } return request.call(this, target, ...args) }; syncBuiltinESMExports();\n`)
    const config = join(root, 'config.json')
    await writeFile(config, JSON.stringify({ version: 1, defaultProfile: 'selected', profiles: { selected: { auth: 'api-key', origin, apiKey: { env: 'TEST_SHODAN_KEY' } } } }), { mode: 0o600 })
    const env = { PATH: process.env.PATH, HOME: root, SHODAN_AXI_CONFIG: config, TEST_SHODAN_KEY: 'fake-secret', NODE_OPTIONS: `--import=${preload}`, NODE_EXTRA_CA_CERTS: certFile }
    const run = (args, overrides = {}) => new Promise((resolve, reject) => {
      const child = spawn(executable, [...args, '--json'], { cwd: root, env: { ...env, ...overrides }, signal: AbortSignal.timeout(10000) })
      let stdout = ''; let stderr = ''
      child.stdout.setEncoding('utf8').on('data', chunk => { stdout += chunk })
      child.stderr.setEncoding('utf8').on('data', chunk => { stderr += chunk })
      child.on('error', reject)
      child.on('close', code => { resolve({ code, stdout, stderr, body: JSON.parse(stdout) }) })
    })
    await check({ root, calls, run, setMode: value => { mode = value } })
  } finally {
    if (server) await new Promise(resolve => server.close(resolve))
    await rm(root, { recursive: true, force: true })
  }
}
