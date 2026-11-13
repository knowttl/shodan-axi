import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { createServer as createHttpServer } from 'node:http'
import { createServer } from 'node:https'
import { connect } from 'node:net'
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { pathToFileURL } from 'node:url'
import { gunzipSync } from 'node:zlib'

const moduleAt = (root, path) => import(pathToFileURL(join(root, path)).href)

test('local Artium uses the packed account tool and refuses unapproved calls', { timeout: 90000 }, async () => {
  const fixtureRoot = process.env.ARTIUM_FIXTURE_ROOT
  const temporary = await mkdtemp(join(tmpdir(), 'shodan-artium-'))
  const previousNodeEnv = process.env.NODE_ENV
  let app, db, fake, healthSchedule, previousHealthTick, tunnel, tunneled
  try {
    const manifest = JSON.parse(process.env.SHODAN_HOSTED_MANIFEST)

    const keyFile = '/test-tls/key.pem'; const caFile = '/test-tls/cert.pem'
    const requests = []
    const members = [{ username: 'existing', email: 'existing@example.test' }]
    const mutations = []
    fake = createServer({ key: await readFile(keyFile), cert: await readFile(caFile) }, (request, response) => {
      const url = new URL(request.url, 'https://localhost')
      requests.push({ path: url.pathname, key: url.searchParams.get('key') })
      response.setHeader('content-type', 'application/json')
      const banner = { ip_str: '192.0.2.7', port: 443, transport: 'tcp', timestamp: '2026-01-01', data: 'synthetic' }
      const banners = [banner, { ...banner, transport: 'udp', timestamp: '2026-01-02' }, { ...banner, timestamp: '2026-01-03' }]
      const bodies = {
        '/api-info': { plan: 'synthetic', query_credits: 20, scan_credits: 98, monitored_ips: 256, usage_limits: { query_credits: -1, scan_credits: -1, monitored_ips: -1 } },
        '/shodan/data': [{ name: 'raw-daily', description: 'Synthetic daily banners', scope: 'daily', unknown: 'private-value' }],
        '/shodan/data/raw-daily': [{ name: 'synthetic.json', size: 10, sha1: 'd68c19a0a345b7eab78d5e11e991c026ec60db63', timestamp: 1793707200000, url: 'https://downloads.example.test/file?signature=private-signature', unknown: 'private-value' }],
        '/account/profile': { member: false, credits: 0, display_name: null, created: '2026-01-01' },
        '/shodan/host/192.0.2.7': { ip_str: '192.0.2.7', ports: [443], data: banners },
        '/shodan/host/count': { total: 2, facets: { port: [{ value: 443, count: 1 }, { value: 80, count: 1 }] } },
        '/shodan/host/search': { total: 2, matches: url.searchParams.get('page') === '2' ? [] : [banner] },
        '/shodan/host/search/facets': ['port', 'country'], '/shodan/host/search/filters': ['asn', 'port'],
        '/shodan/host/search/tokens': { attributes: { ports: [443] }, errors: [], string: '', filters: ['port'] },
        '/shodan/ports': [22, 443], '/dns/domain/example.test': { domain: 'example.test', data: [{ type: 'A', value: '192.0.2.7' }], more: true },
        '/dns/resolve': { 'example.test': '192.0.2.7' }, '/dns/reverse': { '192.0.2.7': ['example.test'] },
        '/tools/httpheaders': { 'User-Agent': 'synthetic' }, '/tools/myip': request.headers['x-test-family'] === 'ipv6' ? '2001:db8::7' : '192.0.2.7',
        '/192.0.2.7': { ip: '192.0.2.7', ports: [443], cpes: [], hostnames: [], tags: [], vulns: ['CVE-2020-0001'] },
        '/labs/honeyscore/192.0.2.7': 0.25, '/shodan/services': { 443: 'https' },
        '/shodan/query': { total: 11, matches: [{ title: 'Synthetic TLS', query: 'port:443' }] },
        '/shodan/query/search': { total: 1, matches: [{ title: 'Synthetic TLS', query: 'port:443' }] },
        '/shodan/query/tags': { total: 1, matches: [{ value: 'test', count: 3 }] },
        '/api/v1/search/filters': ['all', 'has_ipv6'], '/api/v1/search/facets': ['country', 'asn'],
        '/shodan/alert/alert-a/info': { id: 'alert-a', name: 'Synthetic', filters: { ip: ['192.0.2.0/24'] }, triggers: {}, notifiers: [], expiration: null },
        '/shodan/alert/info': [{ id: 'alert-a', name: 'Synthetic', filters: { ip: ['192.0.2.0/24'] }, expiration: null }],
        '/shodan/alert/triggers': [{ name: 'any', rule: '*', description: 'Any service' }],
        '/notifier': { matches: [{ id: 'notifier-a', provider: 'email', args: { to: 'private@example.test' } }], total: 1 },
        '/notifier/provider': { email: { required: ['to'] } },
        '/notifier/notifier-a': { id: 'notifier-a', provider: 'email', args: { to: 'private@example.test' } },
        '/org': { id: 'org-a', name: 'Synthetic Org', admins: [{ username: 'owner', email: 'owner@example.test' }], members, domains: ['example.test'], logo: false, api_key: 'issued-secret' },
        '/shodan/protocols': { https: 'Synthetic HTTPS module' },
        '/shodan/scans': { matches: [{ id: 'scan-a', status: 'PROCESSING', api_key: 'issued-secret' }], total: 2 },
        '/shodan/scan/scan-a': { id: 'scan-a', status: 'PROCESSING', count: 2, api_key: 'issued-secret' },
      }
      const memberEmail = /^\/org\/member\/(.+)$/.exec(url.pathname)?.[1]
      if (memberEmail && request.method !== 'GET') {
        const email = decodeURIComponent(memberEmail)
        mutations.push(`${request.method} ${url.pathname}`)
        if (request.method === 'PUT') members.push({ username: email, email })
        response.end(JSON.stringify({ success: true }))
        return
      }
      response.end(JSON.stringify(bodies[url.pathname]))
    })
    await new Promise(resolve => fake.listen(0, '127.0.0.1', resolve))
    const port = fake.address().port
    const bootstrap = join(temporary, 'route.mjs')
    await writeFile(bootstrap, `import https from 'node:https';\nimport { syncBuiltinESMExports } from 'node:module';\nconst original = https.request;\nhttps.request = function (url, ...args) { if (!(url instanceof URL) || !['https://api.shodan.io', 'https://internetdb.shodan.io', 'https://apiv6.shodan.io', 'https://trends.shodan.io', 'https://exploits.shodan.io'].includes(url.origin)) throw new Error('Unexpected destination'); const target = new URL(url); if (url.origin === 'https://apiv6.shodan.io') { if (args[0].family !== 6) throw new Error('IPv6 was not selected'); args[0].family = 4; args[0].headers = { ...args[0].headers, 'x-test-family': 'ipv6' }; } target.hostname = '127.0.0.1'; target.port = ${port}; args[0].servername = 'localhost'; return original.call(this, target, ...args); };\nsyncBuiltinESMExports();\n`)

    process.env.NODE_ENV = 'test'
    const [{ openStore, createCredentialStore }, { EnvironmentKeyProvider }, { EmbeddedSecretSource }, { createShodanAdapter },
      { SharedIdentityResolver }, { Runner }, { loadTrustedCa }, { Audit }, { toolPaths, healthDefaults }, { createApp }, { seedToolUser, issueTestAccessToken }, { SessionStore }] = await Promise.all([
      moduleAt(fixtureRoot, 'dist/src/server/store/db.js'), moduleAt(fixtureRoot, 'dist/src/server/store/key-provider.js'),
      moduleAt(fixtureRoot, 'dist/src/server/store/secret-source.js'), moduleAt(fixtureRoot, 'dist/src/server/adapters/shodan.js'),
      moduleAt(fixtureRoot, 'dist/src/server/policy/identity-resolver.js'), moduleAt(fixtureRoot, 'dist/src/server/runner/runner.js'),
      moduleAt(fixtureRoot, 'dist/src/server/trusted-ca.js'), moduleAt(fixtureRoot, 'dist/src/server/audit/audit.js'),
      moduleAt(fixtureRoot, 'dist/src/server/config.js'), moduleAt(fixtureRoot, 'dist/src/server/app.js'),
      moduleAt(fixtureRoot, 'dist/test/fixtures/tokens.js'), moduleAt(fixtureRoot, 'dist/src/cli/session.js'),
    ])
    healthSchedule = healthDefaults
    previousHealthTick = healthDefaults.tickMs
    healthDefaults.tickMs = 600000
    const provider = new EnvironmentKeyProvider({ ARTIUM_AXI_MASTER_KEY: Buffer.alloc(32, 1).toString('base64') })
    db = openStore(join(temporary, 'artium.db'), provider)
    await seedToolUser(db)
    const store = createCredentialStore(db, provider)
    store.replaceCredential('shodan-axi', { auth: 'api-key', origin: 'https://api.shodan.io', apiKey: 'hosted-synthetic-key' }, 0, 'synthetic-development-user', Date.now())
    db.prepare("UPDATE tools SET enabled = 1 WHERE name = 'shodan-axi'").run()
    const runner = await Runner.create(join(temporary, 'calls'), loadTrustedCa({ ARTIUM_AXI_EXTRA_CA_FILE: caFile }))
    toolPaths['shodan-axi'] = manifest.toolExecutable
    const source = new EmbeddedSecretSource(store)
    const retrieve = source.getCredential.bind(source)
    let credentialReads = 0
    source.getCredential = async (...args) => { credentialReads++; return retrieve(...args) }
    const adapter = createShodanAdapter(source)
    const prepare = adapter.prepare.bind(adapter)
    adapter.prepare = async (...args) => {
      const call = await prepare(...args)
      if (tunneled) call.environment.HTTPS_PROXY = tunneled, call.environment.NODE_USE_ENV_PROXY = '1'
      return { ...call, args: ['--import', bootstrap, ...call.args] }
    }
    app = createApp({ db, runner, audit: new Audit(db), credentialStore: store, resolver: new SharedIdentityResolver(store, db),
      adapters: [adapter], environment: {} })
    const url = await app.listen({ host: '127.0.0.1', port: 0 })
    const token = issueTestAccessToken(db, 'synthetic-development-user')
    new SessionStore(url, join(temporary, 'artium-axi/session.json')).write({ status: 'authenticated', accessToken: token,
      refreshToken: 'synthetic-refresh', accessExpiresAt: Date.now() + 3600000, familyExpiresAt: Date.now() + 43200000 })
    const run = (args, json = true) => new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [manifest.clientExecutable, 'shodan-axi', ...args, ...(json ? ['--json'] : [])], {
        signal: AbortSignal.timeout(10000),
        env: { PATH: process.env.PATH, HOME: temporary, XDG_CONFIG_HOME: temporary, ARTIUM_AXI_URL: url, ARTIUM_AXI_TEST_HTTP: '1',
          SHODAN_AXI_API_KEY: 'conflicting-developer-key', SHODAN_AXI_AUTH: 'api-key' },
      })
      let stdout = ''; let stderr = ''
      child.stdout.setEncoding('utf8').on('data', chunk => { stdout += chunk })
      child.stderr.setEncoding('utf8').on('data', chunk => { stderr += chunk })
      child.on('error', reject)
      child.on('close', code => { resolve({ code, stdout, stderr }) })
    })
    for (const args of [['init', '--env', 'X'], ['scan', 'submit', '192.0.2.1'], ['info', '--profile', 'other'], ['info', '--origin', 'https://example.test']]) {
      const denied = await run(args)
      assert.notEqual(denied.code, 0)
      assert.equal(credentialReads, 0)
      assert.equal(requests.length, 0)
    }
    db.prepare("DELETE FROM role_tools WHERE tool = 'shodan-axi'").run()
    const withoutGrant = await run(['info'])
    assert.notEqual(withoutGrant.code, 0)
    assert.equal(credentialReads, 0)
    assert.equal(requests.length, 0)
    db.prepare("INSERT INTO role_tools (role_id, tool) VALUES ('synthetic-role', 'shodan-axi')").run()
    const mismatchExecutable = join(temporary, 'mismatched-version.mjs')
    await writeFile(mismatchExecutable, `if (process.argv.slice(2).some(value => ['version', '--version', '-v', '-V'].includes(value))) process.stdout.write('test-2\\n'); else await import(${JSON.stringify(pathToFileURL(bootstrap).href)});\n`)
    toolPaths['shodan-axi'] = mismatchExecutable
    const mismatch = await run(['info'])
    assert.notEqual(mismatch.code, 0, 'A mismatched package pin must refuse admission')
    assert.equal(credentialReads, 0)
    assert.equal(requests.length, 0)
    toolPaths['shodan-axi'] = manifest.toolExecutable
    const info = await run(['info'])
    assert.equal(info.code, 0, info.stdout + info.stderr)
    const infoResult = JSON.parse(info.stdout)
    assert.equal(infoResult.query_credits, 20)
    assert.equal(infoResult.scan_credits, 98)
    const profile = await run(['account', 'profile'])
    assert.equal(profile.code, 0, profile.stdout + profile.stderr)
    const profileResult = JSON.parse(profile.stdout)
    assert.equal(profileResult.credits, 0)
    assert.equal(profileResult.member, false)
    assert.deepEqual(requests, [{ path: '/api-info', key: 'hosted-synthetic-key' }, { path: '/account/profile', key: 'hosted-synthetic-key' }])
    const doctor = await run(['doctor'])
    assert.notEqual(doctor.code, 0)
    const home = await run([])
    assert.equal(JSON.parse(home.stdout).account.query_credits, 20)
    assert.equal(requests.length, 3)
    const packageVersion = JSON.parse(await readFile(join(manifest.installedPackage, 'package.json'), 'utf8')).version
    for (const alias of ['version', '--version', '-v', '-V']) {
      const version = await run([alias], false)
      assert.equal(version.code, 0, version.stdout + version.stderr)
      assert.equal(version.stdout, `${packageVersion}\n`)
    }
    assert.equal(requests.length, 3)
    if (process.env.SHODAN_TEST_SLICE !== 'B1.1') {
      const read = async args => {
        const result = await run(args)
        assert.equal(result.code, 0, result.stdout + result.stderr)
        return JSON.parse(result.stdout)
      }
      const host = await read(['host', '192.0.2.7', '--history'])
      assert.deepEqual(host.banners.map(row => [row.transport, row.timestamp]), [['tcp', '2026-01-01'], ['udp', '2026-01-02'], ['tcp', '2026-01-03']])
      assert.equal((await read(['count', 'port:443', '--facets', 'port:2'])).total, 2)
      assert.equal((await read(['stats', 'port:443', '--facets', 'port:2'])).count, 2)
      assert.deepEqual((await read(['search', 'facets'])).items, ['port', 'country'])
      assert.deepEqual((await read(['search', 'filters'])).items, ['asn', 'port'])
      assert.deepEqual((await read(['search', 'tokens', 'port:443'])).attributes.ports, [443])
      assert.deepEqual((await read(['ports'])).items, [22, 443])
      assert.equal((await read(['dns', 'resolve', 'example.test']))['example.test'], '192.0.2.7')
      assert.deepEqual((await read(['dns', 'reverse', '192.0.2.7']))['192.0.2.7'], ['example.test'])
      assert.equal((await read(['tools', 'headers']))['User-Agent'], 'synthetic')
      assert.equal((await read(['myip'])).addressFamily, 4)
      assert.equal((await read(['myip', '--ipv6'])).addressFamily, 6)
      assert.equal((await read(['search', 'port:443', '--allow-operation', 'OP-003', '--query-credit-budget', '1'])).count, 1)
      assert.equal(requests.at(-1).path, '/shodan/host/search')
      await read(['domain', 'example.test', '--allow-operation', 'OP-040', '--query-credit-budget', '1'])
      assert.equal(requests.at(-1).path, '/dns/domain/example.test')
      const beforeBlocked = requests.length
      const beforeCredentialReads = credentialReads
      for (const args of [
        ['honeyscore', '192.0.2.7', '--allow-operation', 'OP-064', '--accept-unknown-cost', '--max-requests', '1', '--query-credit-budget', '1'],
        ['services', '--allow-operation', 'OP-066', '--accept-unknown-cost', '--max-requests', '1', '--query-credit-budget', '1'],
        ['host', '192.0.2.7', '--save'],
        ['host', '192.0.2.7', '--filename', 'result.json.gz'],
        ['host', 'not-an-address'],
        ['dns', 'resolve', 'a..invalid'],
      ]) {
        const denied = await run(args)
        assert.notEqual(denied.code, 0)
        assert.equal(requests.length, beforeBlocked)
        assert.equal(credentialReads, beforeCredentialReads)
      }
      if (process.env.SHODAN_TEST_SLICE !== 'B2.1') {
        assert.equal((await read(['query', 'list', '--page', '2', '--sort', 'votes', '--order', 'asc'])).items[0].title, 'Synthetic TLS')
        assert.equal((await read(['query', 'search', 'Synthetic TLS'])).items[0].query, 'port:443')
        assert.equal((await read(['query', 'tags', '--size', '1'])).items[0].count, 3)
        assert.deepEqual((await read(['trends', 'filters'])).items, ['all', 'has_ipv6'])
        assert.deepEqual((await read(['trends', 'facets'])).items, ['country', 'asn'])
        const beforeHistory = requests.length
        const beforeHistoryCredentials = credentialReads
        for (const [command, operation] of [[['trends', 'port:443'], 'OP-054'], [['exploits', 'search', 'cve:2020-0001'], 'OP-057'], [['exploits', 'count', 'cve:2020-0001'], 'OP-058']]) {
          assert.notEqual((await run([...command, '--allow-operation', operation, '--query-credit-budget', '1', '--accept-unknown-cost', '--max-requests', '1'])).code, 0)
          assert.equal(requests.length, beforeHistory)
          assert.equal(credentialReads, beforeHistoryCredentials)
        }
      }
      if (['B3.1', 'B3.2', 'B3.3', 'B3.4', 'B4.1', 'B4.2', 'B5.1', 'B5.2'].includes(process.env.SHODAN_TEST_SLICE) || !process.env.SHODAN_TEST_SLICE) {
        assert.equal((await read(['alert', 'info', 'alert-a'])).id, 'alert-a')
        assert.equal((await read(['alert', 'list'])).items[0].id, 'alert-a')
        assert.equal((await read(['alert', 'triggers'])).items[0].rule, '*')
        assert.equal((await read(['notifier', 'list'])).items[0].id, 'notifier-a')
        assert.deepEqual((await read(['notifier', 'providers'])).email.required, ['to'])
        const detail = await read(['notifier', 'get', 'notifier-a'])
        assert.equal(detail.id, 'notifier-a')
        assert.equal(Object.hasOwn(detail, 'args'), false)
        const beforeWrites = requests.length; const beforeWriteCredentials = credentialReads
        for (const args of [
          ['alert', 'create', 'synthetic', '192.0.2.7'], ['alert', 'remove', 'alert-a'], ['alert', 'update', 'alert-a', '192.0.2.7'],
          ['alert', 'enable', 'alert-a', 'any'], ['alert', 'disable', 'alert-a', 'any'], ['alert', 'ignore', 'alert-a', 'any', '192.0.2.7:443'],
          ['alert', 'unignore', 'alert-a', 'any', '192.0.2.7:443'], ['alert', 'notifier', 'add', 'alert-a', 'notifier-a'],
          ['alert', 'notifier', 'remove', 'alert-a', 'notifier-a'], ['notifier', 'create', '--body-file', 'input.json'],
          ['notifier', 'remove', 'notifier-a'], ['notifier', 'update', 'notifier-a', '--body-file', 'input.json'],
          ['alert', 'ignore', 'alert-a', 'any', '192.0.2.7:443', '--vulns', 'CVE-2020-0001'], ['alert', 'clear'],
          ['alert', 'domain', 'example.test'], ['alert', 'import', 'input.json'],
        ]) {
          for (const supplied of [args, [...args, '--allow-operation', 'OP-013,OP-015,OP-016,OP-019,OP-020,OP-021,OP-022,OP-023,OP-024,OP-027,OP-028,OP-030,OP-070', '--accept-unknown-cost', '--query-credit-budget', '20', '--max-requests', '40', '--execute', '--confirm', '00000000-0000-4000-8000-000000000001']]) {
            assert.notEqual((await run(supplied)).code, 0)
            assert.equal(requests.length, beforeWrites, JSON.stringify(supplied))
            assert.equal(credentialReads, beforeWriteCredentials, JSON.stringify(supplied))
          }
        }
      }
      if (['B3.2', 'B3.3', 'B3.4', 'B4.1', 'B4.2', 'B5.1', 'B5.2'].includes(process.env.SHODAN_TEST_SLICE) || !process.env.SHODAN_TEST_SLICE) {
        const info = await read(['org', 'info'])
        assert.equal(info.members[0].email, 'existing@example.test')
        assert.equal(Object.hasOwn(info, 'api_key'), false)
        const before = requests.length; const beforeCredentials = credentialReads
        for (const args of [
          ['org', 'add', 'new@example.test'], ['org', 'add', 'new@example.test', '--silent'],
          ['org', 'remove', 'existing@example.test'],
          ['org', 'add', 'new@example.test', '--allow-operation', 'OP-037', '--accept-unknown-cost', '--query-credit-budget', '1', '--max-requests', '3', '--execute', '--confirm', '00000000-0000-4000-8000-000000000001'],
          ['org', 'remove', 'existing@example.test', '--allow-operation', 'OP-038', '--accept-unknown-cost', '--query-credit-budget', '1', '--max-requests', '3', '--execute', '--confirm', '00000000-0000-4000-8000-000000000001'],
        ]) {
          assert.notEqual((await run(args)).code, 0)
          assert.equal(requests.length, before, JSON.stringify(args))
          assert.equal(credentialReads, beforeCredentials, JSON.stringify(args))
        }
      }
      if (['B3.3', 'B3.4', 'B4.1', 'B4.2', 'B5.1', 'B5.2'].includes(process.env.SHODAN_TEST_SLICE) || !process.env.SHODAN_TEST_SLICE) {
        assert.equal((await read(['scan', 'protocols'])).https, 'Synthetic HTTPS module')
        const list = await read(['scan', 'list'])
        assert.equal(list.items[0].id, 'scan-a')
        assert.equal(list.complete, false)
        assert.equal(Object.hasOwn(list.items[0], 'api_key'), false)
        assert.equal((await read(['scan', 'status', 'scan-a'])).status, 'PROCESSING')
        const before = requests.length; const beforeCredentials = credentialReads
        for (const args of [
          ['scan', 'submit', '192.0.2.0/31'], ['scan', 'internet', '443', 'https'],
          ['scan', 'submit', '192.0.2.0/31', '--force', '--allow-operation', 'OP-009', '--scan-credit-budget', '2', '--max-requests', '1', '--execute', '--confirm', '00000000-0000-4000-8000-000000000001'],
          ['scan', 'internet', '443', 'https', '--allow-operation', 'OP-010', '--scan-credit-budget', '1', '--accept-unknown-cost', '--max-requests', '1', '--execute', '--confirm', '00000000-0000-4000-8000-000000000001'],
        ]) {
          assert.notEqual((await run(args)).code, 0)
          assert.equal(requests.length, before, JSON.stringify(args))
          assert.equal(credentialReads, beforeCredentials, JSON.stringify(args))
        }
      }
      if (['B3.4', 'B4.1', 'B4.2', 'B5.1', 'B5.2'].includes(process.env.SHODAN_TEST_SLICE) || !process.env.SHODAN_TEST_SLICE) {
        const before = requests.length; const beforeCredentials = credentialReads
        for (const [command, target, operation] of [
          ['ping', '192.0.2.7', 'OP-060'], ['geoping', '192.0.2.7', 'OP-061'],
          ['dns', 'service.example.test', 'OP-062'], ['geodns', 'service.example.test', 'OP-063'],
        ]) {
          for (const flags of [[], ['--allow-operation', operation, '--max-requests', '1', '--execute', '--confirm', '00000000-0000-4000-8000-000000000001']]) {
            assert.notEqual((await run(['geonet', command, target, ...flags])).code, 0)
            assert.equal(requests.length, before, command)
            assert.equal(credentialReads, beforeCredentials, command)
          }
        }
      }
      if (['B4.1', 'B4.2', 'B5.1', 'B5.2'].includes(process.env.SHODAN_TEST_SLICE) || !process.env.SHODAN_TEST_SLICE) {
        const stats = await read(['alert', 'stats'])
        assert.equal(stats.complete, false)
        assert.equal(stats.aggregation, 'partial')
        const before = requests.length; const beforeCredentials = credentialReads
        for (const args of [
          ['parse', 'input.json.gz'], ['parse', '/tmp/input.json.gz', '--filename', '/tmp/result.json.gz'],
          ['convert', 'input.json.gz', 'csv'], ['convert', '/tmp/input.json.gz', 'xlsx', '--filename', '/tmp/result.xlsx'],
          ['alert', 'export', '--filename', '/tmp/alerts.json.gz'],
        ]) {
          assert.notEqual((await run(args)).code, 0)
          assert.equal(requests.length, before, JSON.stringify(args))
          assert.equal(credentialReads, beforeCredentials, JSON.stringify(args))
        }
      }
      if (['B4.2', 'B5.1', 'B5.2'].includes(process.env.SHODAN_TEST_SLICE) || !process.env.SHODAN_TEST_SLICE) {
        const datasets = await read(['data', 'list'])
        assert.deepEqual(datasets.items, [{ name: 'raw-daily', description: 'Synthetic daily banners', scope: 'daily' }])
        const files = await read(['data', 'list', '--dataset', 'raw-daily'])
        assert.deepEqual(files.items, [{ name: 'synthetic.json', size: 10, sha1: 'd68c19a0a345b7eab78d5e11e991c026ec60db63', timestamp: 1793707200000 }])
        assert.doesNotMatch(JSON.stringify(files), /private-signature|private-value|downloads\.example/)
        const before = requests.length; const beforeCredentials = credentialReads
        for (const args of [['download', 'port:443'], ['alert', 'download'], ['data', 'download', 'raw-daily', 'synthetic.json']]) {
          assert.notEqual((await run(args)).code, 0)
          assert.equal(requests.length, before)
          assert.equal(credentialReads, beforeCredentials)
        }
      }
      if (['B5.1', 'B5.2'].includes(process.env.SHODAN_TEST_SLICE) || !process.env.SHODAN_TEST_SLICE) {
        const before = requests.length; const beforeCredentials = credentialReads
        const selectors = [[['stream'], 'OP-046'], [['stream', '--asn', '64500'], 'OP-047'], [['stream', '--countries', 'CA'], 'OP-048'], [['stream', '--ports', '443'], 'OP-049'], [['stream', '--vulns', 'CVE-2020-0001'], 'OP-050'], [['stream', '--custom-filters', 'port:443'], 'OP-051'], [['stream', '--alert', 'all'], 'OP-052'], [['stream', '--alert', 'alert-a'], 'OP-053'], [['stream', '--tags', 'cloud'], 'OP-065'], [['threatnet', 'events'], 'OP-067'], [['threatnet', 'backscatter'], 'OP-068'], [['threatnet', 'ssh'], 'OP-069']]
        for (const [args, operation] of selectors) {
          for (const flags of [[], ['--allow-operation', operation, '--accept-unknown-cost', '--limit', '2', '--max-bytes', '1000', '--timeout', '5000', '--idle-timeout', '3000', '--execute', '--confirm', '00000000-0000-4000-8000-000000000001']]) {
            assert.notEqual((await run([...args, ...flags])).code, 0)
            assert.equal(requests.length, before, JSON.stringify(args))
            assert.equal(credentialReads, beforeCredentials, JSON.stringify(args))
          }
        }
      }
      store.replaceCredential('shodan-axi', { auth: 'none', origin: 'https://api.shodan.io' }, 1, 'synthetic-development-user', Date.now())
      const snapshot = await read(['internetdb', 'host', '192.0.2.7'])
      assert.deepEqual(snapshot.vulns, ['CVE-2020-0001'])
      assert.equal(requests.at(-1).key, null)
      if (['B6.1'].includes(process.env.SHODAN_TEST_SLICE) || !process.env.SHODAN_TEST_SLICE) {
        store.replaceCredential('shodan-axi', { auth: 'api-key', origin: 'https://api.shodan.io', apiKey: 'hosted-synthetic-key' }, 2, 'synthetic-development-user', Date.now())
        tunnel = createHttpServer().on('connect', (_request, client, head) => {
          const upstream = connect(port, '127.0.0.1', () => { client.write('HTTP/1.1 200 Connection Established\r\n\r\n'); upstream.write(head); upstream.pipe(client); client.pipe(upstream) })
          upstream.on('error', () => client.destroy()); client.on('error', () => upstream.destroy())
        })
        await new Promise(resolve => tunnel.listen(0, '127.0.0.1', resolve))
        tunneled = `http://127.0.0.1:${tunnel.address().port}`
        const post = async (path, payload) => {
          const response = await app.inject({ method: 'POST', url: `/v1/tools/shodan-axi/${path}`, headers: { authorization: `Bearer ${token}` }, payload })
          return { status: response.statusCode, body: response.json() }
        }
        const configure = settings => db.prepare("UPDATE tools SET native_settings = ? WHERE name = 'shodan-axi'").run(JSON.stringify(settings))
        const grants = { 'synthetic-development-user': ['OP-037'] }
        const add = { command: 'org add', arguments: ['new@example.test'], queryCreditBudget: 1, maxRequests: 3, silent: true }
        const download = { command: 'download', query: 'port:443', limit: 2, maxBytes: 100000, queryCreditBudget: 1, maxRequests: 3 }
        const before = requests.length; const beforeCredentials = credentialReads
        configure({})
        for (const [route, payload] of [['writes/preview', add], ['exports/preview', download]]) {
          const denied = await post(route, payload)
          assert.ok(denied.status >= 400, route)
          assert.equal(requests.length, before, route)
          assert.equal(credentialReads, beforeCredentials, route)
        }
        configure({ writes: { grants, maxQueryCredits: 2, maxRequests: 6 }, exports: { grants: { 'synthetic-development-user': ['CLI-005'] }, maxQueryCredits: 2, maxRequests: 6, maxRecords: 10, maxBytes: 100000, retentionSeconds: 60 } })
        for (const payload of [{ ...add, command: 'org remove', arguments: ['existing@example.test'] }, { ...add, maxRequests: 7 }, { ...add, queryCreditBudget: 3 }]) {
          assert.ok((await post('writes/preview', payload)).status >= 400, JSON.stringify(payload))
          assert.equal(requests.length, before, JSON.stringify(payload))
        }
        const preview = await post('writes/preview', add)
        assert.equal(preview.status, 200)
        assert.deepEqual(mutations, [])
        const executed = await post('writes/execute', { ...add, confirm: preview.body.confirm })
        assert.equal(executed.body.status, 'completed')
        assert.deepEqual(mutations, ['PUT /org/member/new%40example.test'])
        assert.ok(members.some(member => member.email === 'new@example.test'))
        assert.ok((await post('writes/execute', { ...add, confirm: preview.body.confirm })).status >= 400)
        assert.deepEqual(mutations, ['PUT /org/member/new%40example.test'])
        db.prepare("UPDATE credentials SET read_only = 1 WHERE tool = 'shodan-axi'").run()
        const afterWrite = requests.length
        assert.ok((await post('writes/preview', { ...add, arguments: ['other@example.test'] })).status >= 400)
        assert.equal(requests.length, afterWrite)
        db.prepare("UPDATE credentials SET read_only = 0 WHERE tool = 'shodan-axi'").run()
        const exportPreview = await post('exports/preview', download)
        assert.equal(exportPreview.status, 200)
        const started = await post('exports/start', { ...download, confirm: exportPreview.body.confirm })
        assert.equal(started.status, 200)
        const exportUrl = `/v1/tools/shodan-axi/exports/${started.body.id}`
        const headers = { authorization: `Bearer ${token}` }
        const finished = (await app.inject({ method: 'GET', url: `${exportUrl}?waitMs=20000`, headers })).json()
        assert.equal(finished.state, 'partial')
        assert.deepEqual([finished.result.count, finished.result.total, finished.result.complete], [1, 2, false])
        const retrieved = await app.inject({ method: 'POST', url: `${exportUrl}/retrieve`, headers, payload: {} })
        assert.equal(retrieved.statusCode, 200)
        assert.equal(retrieved.headers['x-artium-export-complete'], 'false')
        assert.equal(createHash('sha256').update(retrieved.rawPayload).digest('hex'), finished.result.sha256)
        assert.equal(JSON.parse(gunzipSync(retrieved.rawPayload).toString().trim()).ip_str, '192.0.2.7')
        assert.ok((await app.inject({ method: 'POST', url: `${exportUrl}/retrieve`, headers, payload: {} })).statusCode >= 400)
        assert.doesNotMatch(JSON.stringify(db.prepare('SELECT * FROM audit').all()), /new@example\.test|other@example\.test|port:443/)
      }
    }
    if (process.env.ARTIUM_EXPECT_B1_1_READS) {
      assert.deepEqual(requests.map(request => request.path), ['/api-info', '/account/profile', '/api-info'])
    }
    assert.doesNotMatch(info.stdout + profile.stdout + JSON.stringify(db.prepare('SELECT * FROM audit').all()), /hosted-synthetic-key|conflicting-developer-key/)
    assert.deepEqual(await readdir(join(temporary, 'calls')), [])
  } finally {
    if (previousNodeEnv === undefined) delete process.env.NODE_ENV
    else process.env.NODE_ENV = previousNodeEnv
    if (app) await app.close()
    if (healthSchedule) healthSchedule.tickMs = previousHealthTick
    if (db) db.close()
    if (tunnel) await new Promise(resolve => { tunnel.close(resolve); tunnel.closeAllConnections() })
    if (fake) await new Promise(resolve => fake.close(resolve))
    await rm(temporary, { recursive: true, force: true })
  }
})
