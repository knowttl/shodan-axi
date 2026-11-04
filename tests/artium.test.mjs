import assert from 'node:assert/strict'
import { execFileSync, spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { createServer } from 'node:https'
import { mkdtemp, mkdir, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { isAbsolute, join, resolve } from 'node:path'
import { test } from 'node:test'
import { pathToFileURL } from 'node:url'

const hash = value => createHash('sha256').update(value).digest('hex')
const moduleAt = (root, path) => import(pathToFileURL(join(root, path)).href)

async function files(directory, prefix = '') {
  const result = []
  for (const entry of await readdir(join(directory, prefix), { withFileTypes: true })) {
    const name = join(prefix, entry.name)
    if (entry.isDirectory()) result.push(...await files(directory, name))
    else if (entry.isFile()) result.push(name)
    else throw new Error('Package contains a non-file entry')
  }
  return result.sort()
}

test('local Artium uses the packed account tool and refuses unapproved calls', { timeout: 45000 }, async () => {
  const fixtureRoot = process.env.ARTIUM_FIXTURE_ROOT
  const manifestPath = process.env.ARTIUM_FIXTURE_MANIFEST
  assert.ok(fixtureRoot && isAbsolute(fixtureRoot) && manifestPath && isAbsolute(manifestPath), 'Set absolute Artium fixture root and manifest paths')
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'))
  for (const key of ['tarball', 'installedPackage', 'serverModule', 'clientExecutable', 'toolExecutable']) {
    assert.ok(isAbsolute(manifest[key]), `Manifest requires an absolute ${key}`)
  }
  assert.equal(hash(await readFile(manifest.tarball)), manifest.sha256)
  assert.equal(execFileSync('git', ['-C', fixtureRoot, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(), manifest.artiumRevision)
  assert.equal(execFileSync('git', ['-C', fixtureRoot, 'status', '--porcelain'], { encoding: 'utf8' }).trim(), '', 'Artium fixture source must match its committed revision')
  assert.equal(await realpath(manifest.installedPackage), resolve(manifest.installedPackage), 'Host package must not be a symlink')
  const temporary = await mkdtemp(join(tmpdir(), 'shodan-artium-'))
  const previousNodeEnv = process.env.NODE_ENV
  let app, db, fake, healthSchedule, previousHealthTick
  try {
    const packed = JSON.parse(execFileSync('npm', ['pack', '--ignore-scripts', '--pack-destination', temporary, '--json'], { encoding: 'utf8' }))
    assert.equal(hash(await readFile(join(temporary, packed[0].filename))), manifest.sha256, 'Current tarball differs from the host package')
    const extracted = join(temporary, 'extract')
    await mkdir(extracted)
    execFileSync('tar', ['-xzf', manifest.tarball, '-C', extracted])
    const packageRoot = join(extracted, 'package')
    const packageFiles = await files(packageRoot)
    assert.deepEqual(await files(manifest.installedPackage), packageFiles)
    for (const file of packageFiles) assert.deepEqual(await readFile(join(packageRoot, file)), await readFile(join(manifest.installedPackage, file)), file)
    assert.equal(await realpath(manifest.toolExecutable), await realpath(join(manifest.installedPackage, 'bin/shodan-axi.js')))
    assert.equal(await realpath(manifest.serverModule), await realpath(join(fixtureRoot, 'dist/src/server/app.js')))
    assert.equal(await realpath(manifest.clientExecutable), await realpath(join(fixtureRoot, 'dist/cli/artium-axi.mjs')))
    const inventory = JSON.parse(await readFile(join(fixtureRoot, 'tools/inventories/shodan-axi.json'), 'utf8'))
    assert.deepEqual(JSON.parse(await readFile(join(fixtureRoot, 'dist/tools/inventories/shodan-axi.json'), 'utf8')), inventory)
    for (const item of inventory.sources) assert.equal(hash(await readFile(join(manifest.installedPackage, item.path))), item.sha256, item.path)

    const keyFile = join(temporary, 'fake-key.pem')
    const caFile = join(temporary, 'fake-ca.pem')
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyFile, '-out', caFile, '-days', '1',
      '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost', '-addext', 'basicConstraints=critical,CA:TRUE',
      '-addext', 'keyUsage=critical,keyCertSign,cRLSign,digitalSignature'], { stdio: 'ignore' })
    const requests = []
    fake = createServer({ key: await readFile(keyFile), cert: await readFile(caFile) }, (request, response) => {
      const url = new URL(request.url, 'https://localhost')
      requests.push({ path: url.pathname, key: url.searchParams.get('key') })
      response.setHeader('content-type', 'application/json')
      const banner = { ip_str: '192.0.2.7', port: 443, transport: 'tcp', timestamp: '2026-01-01', data: 'synthetic' }
      const banners = [banner, { ...banner, transport: 'udp', timestamp: '2026-01-02' }, { ...banner, timestamp: '2026-01-03' }]
      const bodies = {
        '/api-info': { plan: 'synthetic', query_credits: 20, scan_credits: 98, monitored_ips: 256, usage_limits: { query_credits: -1, scan_credits: -1, monitored_ips: -1 } },
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
      }
      response.end(JSON.stringify(bodies[url.pathname]))
    })
    await new Promise(resolve => fake.listen(0, '127.0.0.1', resolve))
    const port = fake.address().port
    const bootstrap = join(temporary, 'route.mjs')
    await writeFile(bootstrap, `import https from 'node:https';\nimport { syncBuiltinESMExports } from 'node:module';\nconst original = https.request;\nhttps.request = function (url, ...args) { if (!(url instanceof URL) || !['https://api.shodan.io', 'https://internetdb.shodan.io', 'https://apiv6.shodan.io', 'https://trends.shodan.io', 'https://exploits.shodan.io'].includes(url.origin)) throw new Error('Unexpected destination'); const target = new URL(url); if (url.origin === 'https://apiv6.shodan.io') { if (args[0].family !== 6) throw new Error('IPv6 was not selected'); args[0].family = 4; args[0].headers = { ...args[0].headers, 'x-test-family': 'ipv6' }; } target.hostname = '127.0.0.1'; target.port = ${port}; args[0].servername = 'localhost'; return original.call(this, target, ...args); };\nsyncBuiltinESMExports();\nawait import(${JSON.stringify(pathToFileURL(manifest.toolExecutable).href)});\n`)

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
    toolPaths['shodan-axi'] = bootstrap
    const source = new EmbeddedSecretSource(store)
    const retrieve = source.getCredential.bind(source)
    let credentialReads = 0
    source.getCredential = async (...args) => { credentialReads++; return retrieve(...args) }
    app = createApp({ db, runner, audit: new Audit(db), credentialStore: store, resolver: new SharedIdentityResolver(store),
      adapters: [createShodanAdapter(source)], environment: {} })
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
    db.prepare("INSERT INTO role_tools VALUES ('synthetic-role', 'shodan-axi')").run()
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
    assert.equal(JSON.parse(doctor.stdout).status, 'ok')
    const home = await run([])
    assert.equal(JSON.parse(home.stdout).account.query_credits, 20)
    assert.equal(requests.length, 4)
    for (const alias of ['version', '--version', '-v', '-V']) {
      const version = await run([alias], false)
      assert.equal(version.code, 0, version.stdout + version.stderr)
      assert.equal(version.stdout, `${packed[0].version}\n`)
    }
    assert.equal(requests.length, 4)
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
      const beforeBlocked = requests.length
      const beforeCredentialReads = credentialReads
      for (const args of [
        ['search', 'port:443', '--allow-operation', 'OP-003', '--query-credit-budget', '1'],
        ['domain', 'example.test', '--allow-operation', 'OP-040', '--query-credit-budget', '1'],
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
      if (process.env.SHODAN_TEST_SLICE === 'B3.1' || !process.env.SHODAN_TEST_SLICE) {
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
      store.replaceCredential('shodan-axi', { auth: 'none', origin: 'https://api.shodan.io' }, 1, 'synthetic-development-user', Date.now())
      const snapshot = await read(['internetdb', 'host', '192.0.2.7'])
      assert.deepEqual(snapshot.vulns, ['CVE-2020-0001'])
      assert.equal(requests.at(-1).key, null)
    }
    assert.doesNotMatch(info.stdout + profile.stdout + JSON.stringify(db.prepare('SELECT * FROM audit').all()), /hosted-synthetic-key|conflicting-developer-key/)
    assert.deepEqual(await readdir(join(temporary, 'calls')), [])
  } finally {
    if (previousNodeEnv === undefined) delete process.env.NODE_ENV
    else process.env.NODE_ENV = previousNodeEnv
    if (app) await app.close()
    if (healthSchedule) healthSchedule.tickMs = previousHealthTick
    if (db) db.close()
    if (fake) await new Promise(resolve => fake.close(resolve))
    await rm(temporary, { recursive: true, force: true })
  }
})
