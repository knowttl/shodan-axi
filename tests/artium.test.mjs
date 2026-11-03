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

test('local Artium uses the packed account tool and refuses unapproved calls', { timeout: 30000 }, async () => {
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
  let app, db, fake
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
      response.end(JSON.stringify(url.pathname === '/api-info'
        ? { plan: 'synthetic', query_credits: 20, scan_credits: 98, monitored_ips: 256, usage_limits: { query_credits: -1, scan_credits: -1, monitored_ips: -1 } }
        : { member: false, credits: 0, display_name: null, created: '2026-01-01' }))
    })
    await new Promise(resolve => fake.listen(0, 'localhost', resolve))
    const port = fake.address().port
    const bootstrap = join(temporary, 'route.mjs')
    await writeFile(bootstrap, `import https from 'node:https';\nimport { syncBuiltinESMExports } from 'node:module';\nconst original = https.request;\nhttps.request = function (url, ...args) { if (!(url instanceof URL) || url.origin !== 'https://api.shodan.io') throw new Error('Unexpected destination'); const target = new URL(url); target.hostname = 'localhost'; target.port = ${port}; return original.call(this, target, ...args); };\nsyncBuiltinESMExports();\nawait import(${JSON.stringify(pathToFileURL(manifest.toolExecutable).href)});\n`)

    process.env.NODE_ENV = 'test'
    const [{ openStore, createCredentialStore }, { EnvironmentKeyProvider }, { EmbeddedSecretSource }, { createShodanAdapter },
      { SharedIdentityResolver }, { Runner }, { loadTrustedCa }, { Audit }, { toolPaths }, { createApp }, { seedToolUser, issueTestAccessToken }, { SessionStore }] = await Promise.all([
      moduleAt(fixtureRoot, 'dist/src/server/store/db.js'), moduleAt(fixtureRoot, 'dist/src/server/store/key-provider.js'),
      moduleAt(fixtureRoot, 'dist/src/server/store/secret-source.js'), moduleAt(fixtureRoot, 'dist/src/server/adapters/shodan.js'),
      moduleAt(fixtureRoot, 'dist/src/server/policy/identity-resolver.js'), moduleAt(fixtureRoot, 'dist/src/server/runner/runner.js'),
      moduleAt(fixtureRoot, 'dist/src/server/trusted-ca.js'), moduleAt(fixtureRoot, 'dist/src/server/audit/audit.js'),
      moduleAt(fixtureRoot, 'dist/src/server/config.js'), moduleAt(fixtureRoot, 'dist/src/server/app.js'),
      moduleAt(fixtureRoot, 'dist/test/fixtures/tokens.js'), moduleAt(fixtureRoot, 'dist/src/cli/session.js'),
    ])
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
    for (const args of [['init', '--env', 'X'], ['host', '192.0.2.1'], ['info', '--profile', 'other'], ['info', '--origin', 'https://example.test']]) {
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
      assert.equal(version.stdout, '0.1.0\n')
    }
    assert.equal(requests.length, 4)
    assert.doesNotMatch(info.stdout + profile.stdout + JSON.stringify(db.prepare('SELECT * FROM audit').all()), /hosted-synthetic-key|conflicting-developer-key/)
    assert.deepEqual(await readdir(join(temporary, 'calls')), [])
  } finally {
    if (previousNodeEnv === undefined) delete process.env.NODE_ENV
    else process.env.NODE_ENV = previousNodeEnv
    if (app) await app.close()
    if (db) db.close()
    if (fake) await new Promise(resolve => fake.close(resolve))
    await rm(temporary, { recursive: true, force: true })
  }
})
