import assert from 'node:assert/strict'
import { execFileSync, spawn } from 'node:child_process'
import { createServer } from 'node:https'
import { mkdtemp, readFile, rm, writeFile, chmod, symlink, mkdir } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { createTestTls } from './tls-fixture.mjs'

test('packaged account reads use the selected secret and preserve values', async () => {
  const root = await mkdtemp(join(tmpdir(), 'shodan-test-'))
  const tarball = execFileSync('npm', ['pack', '--ignore-scripts', '--pack-destination', root, '--json'], { encoding: 'utf8' })
  const packageDetails = JSON.parse(tarball)[0]
  const packageFile = join(root, packageDetails.filename)
  execFileSync('npm', ['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--prefix', root, packageFile], { stdio: 'ignore' })
  const executable = join(root, 'node_modules', '.bin', 'shodan-axi')
  const { keyFile, certFile } = await createTestTls(root, 'IP:127.0.0.1')
  const calls = []
  const accountKey = 'synthetic-"/+= secret'
  let malformed = false
  let cliExample = false
  let failure = ''
  const server = createServer({ key: await readFile(keyFile), cert: await readFile(certFile) }, (request, response) => {
    const url = new URL(request.url, 'https://localhost')
    calls.push({ path: url.pathname, key: url.searchParams.get('key') })
    if (failure === 'denied') { response.writeHead(403); response.end(accountKey); return }
    if (failure === 'redirect') { response.writeHead(302, { location: `https://127.0.0.1:${server.address().port}/unexpected` }); response.end(accountKey); return }
    response.setHeader('content-type', 'application/json')
    response.end(JSON.stringify(malformed ? { plan: 'invalid' } : url.pathname === '/api-info'
      ? { plan: 'synthetic', query_credits: cliExample ? 7 : 20, scan_credits: cliExample ? 3 : 98, monitored_ips: 256, usage_limits: { query_credits: -1, scan_credits: -1, monitored_ips: -1 }, nested: { echo: accountKey, encoded: encodeURIComponent(accountKey), form: new URLSearchParams({ key: accountKey }).toString().slice(4), escaped: JSON.stringify(accountKey).slice(1, -1) } }
      : { member: false, credits: 0, display_name: null, created: '2026-01-01' }))
  })
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  const config = join(root, 'config.json')
  await writeFile(config, JSON.stringify({ version: 1, defaultProfile: 'selected', profiles: { selected: {
    auth: 'api-key', origin: `https://127.0.0.1:${address.port}`, apiKey: { env: 'TEST_ACCOUNT_KEY' },
  } } }), { mode: 0o600 })
  const env = { ...process.env, SHODAN_AXI_CONFIG: config, TEST_ACCOUNT_KEY: accountKey, SHODAN_AXI_API_KEY: 'conflicting-secret',
    SHODAN_AXI_PROFILE: undefined, SHODAN_AXI_AUTH: undefined, SHODAN_AXI_ORIGIN: undefined, SHODAN_AXI_STREAM_ORIGIN: undefined,
    SHODAN_AXI_READ_ONLY: 'true', NODE_OPTIONS: undefined, NODE_EXTRA_CA_CERTS: certFile }
  const run = (args, overrides = {}) => new Promise((resolve, reject) => {
    const child = spawn(executable, [...args, '--json'], { env: { ...env, ...overrides } })
    let stdout = ''
    child.stdout.setEncoding('utf8').on('data', chunk => { stdout += chunk })
    child.on('error', reject)
    child.on('close', code => { resolve({ code, stdout }) })
  })
  try {
    for (const alias of ['version', '--version', '-v', '-V']) {
      assert.equal(execFileSync(executable, [alias], { encoding: 'utf8', env: { ...env, SHODAN_AXI_CONFIG: '/nonexistent/invalid' } }), `${packageDetails.version}\n`)
    }
    const rawInit = await run(['init', 'inline-secret'])
    assert.equal(rawInit.code, 2)
    assert.doesNotMatch(rawInit.stdout, /inline-secret/)
    const initConfig = join(root, 'init.json')
    const initialized = await run(['init', '--config', initConfig, '--env', 'TEST_ACCOUNT_KEY'])
    assert.equal(initialized.code, 0)
    assert.deepEqual(JSON.parse(await readFile(initConfig, 'utf8')).profiles.default.apiKey, { env: 'TEST_ACCOUNT_KEY' })
    const configured = await run(['profile', 'set', 'other', '--env', 'TEST_ACCOUNT_KEY'])
    assert.equal(configured.code, 0)
    const listed = await run(['profile', 'list'])
    assert.deepEqual(JSON.parse(listed.stdout).profiles, ['selected', 'other'])
    const status = await run(['auth', 'status', '--profile', 'selected'])
    assert.equal(JSON.parse(status.stdout).apiKey.env, 'TEST_ACCOUNT_KEY')
    assert.doesNotMatch(status.stdout, /synthetic-secret|conflicting-secret/)
    const badFlag = await run(['info', '--api-key', 'synthetic-secret'])
    assert.equal(badFlag.code, 2)
    assert.doesNotMatch(badFlag.stdout, /synthetic-secret/)
    const badBoolean = await run(['info', '--profile', 'selected'], { SHODAN_AXI_READ_ONLY: 'invalid' })
    assert.equal(JSON.parse(badBoolean.stdout).error, 'CONFIG_INVALID')
    assert.equal(calls.length, 0)
    const info = await run(['info', '--profile', 'selected'])
    assert.equal(info.code, 0)
    assert.equal(JSON.parse(info.stdout).query_credits, 20)
    assert.equal(JSON.parse(info.stdout).scan_credits, 98)
    const profile = await run(['account', 'profile', '--profile', 'selected'])
    assert.equal(profile.code, 0)
    assert.equal(JSON.parse(profile.stdout).credits, 0)
    assert.equal(JSON.parse(profile.stdout).member, false)
    assert.equal(JSON.parse(profile.stdout).display_name, null)
    assert.deepEqual(calls, [{ path: '/api-info', key: accountKey }, { path: '/account/profile', key: accountKey }])
    for (const form of [accountKey, encodeURIComponent(accountKey), new URLSearchParams({ key: accountKey }).toString().slice(4), JSON.stringify(accountKey).slice(1, -1), 'conflicting-secret']) {
      assert.ok(!(info.stdout + profile.stdout).includes(form))
    }
    const doctor = await run(['doctor', '--profile', 'selected'])
    assert.equal(JSON.parse(doctor.stdout).status, 'ok')
    assert.equal(calls.length, 3)
    cliExample = true
    const example = await run(['info', '--profile', 'selected'])
    assert.equal(JSON.parse(example.stdout).query_credits, 7)
    assert.equal(JSON.parse(example.stdout).scan_credits, 3)
    cliExample = false
    const environmentProfile = await run(['info'], { SHODAN_AXI_API_KEY: accountKey, SHODAN_AXI_ORIGIN: `https://127.0.0.1:${address.port}` })
    assert.equal(JSON.parse(environmentProfile.stdout).query_credits, 20)
    const secretFile = join(root, 'secret')
    await writeFile(secretFile, 'file-secret\n', { mode: 0o600 })
    assert.equal((await run(['profile', 'set', 'file-profile', '--file', secretFile])).code, 0)
    const fileConfig = JSON.parse(await readFile(config, 'utf8'))
    fileConfig.profiles['file-profile'].origin = `https://127.0.0.1:${address.port}`
    await writeFile(config, JSON.stringify(fileConfig), { mode: 0o600 })
    assert.equal((await run(['info', '--profile', 'file-profile'])).code, 0)
    assert.equal(calls.at(-1).key, 'file-secret')
    await chmod(secretFile, 0o644)
    const insecure = await run(['info', '--profile', 'file-profile'])
    assert.equal(JSON.parse(insecure.stdout).error, 'CONFIG_INSECURE')
    const link = join(root, 'secret-link')
    await symlink(secretFile, link)
    fileConfig.profiles['file-profile'].apiKey = { file: link }
    await writeFile(config, JSON.stringify(fileConfig))
    const linked = await run(['info', '--profile', 'file-profile'])
    assert.equal(JSON.parse(linked.stdout).error, 'CONFIG_INSECURE')
    await mkdir(join(root, '.shodan'))
    await writeFile(join(root, '.shodan', 'api_key'), 'old-key')
    const noCredentials = await run(['info'], { HOME: root, SHODAN_AXI_CONFIG: join(root, 'missing'), SHODAN_AXI_API_KEY: undefined,
      SHODAN_AXI_AUTH: undefined, SHODAN_AXI_ORIGIN: undefined, SHODAN_AXI_PROFILE: undefined })
    assert.equal(JSON.parse(noCredentials.stdout).error, 'AUTH_REQUIRED')
    assert.doesNotMatch(noCredentials.stdout, /old-key/)
    const partial = await run(['info'], { SHODAN_AXI_CONFIG: join(root, 'missing'), SHODAN_AXI_API_KEY: undefined,
      SHODAN_AXI_AUTH: undefined, SHODAN_AXI_ORIGIN: 'https://127.0.0.1:1', SHODAN_AXI_PROFILE: undefined })
    assert.equal(JSON.parse(partial.stdout).error, 'CONFIG_INVALID')
    const inlineConfig = join(root, 'inline.json')
    await writeFile(inlineConfig, JSON.stringify({ version: 1, profiles: { bad: { auth: 'api-key', apiKey: 'inline-secret' } } }), { mode: 0o600 })
    const inline = await run(['info', '--config', inlineConfig, '--profile', 'bad'])
    assert.equal(JSON.parse(inline.stdout).error, 'CONFIG_INVALID')
    assert.doesNotMatch(inline.stdout, /inline-secret/)
    failure = 'denied'
    const deniedByVendor = await run(['info', '--profile', 'selected'])
    assert.equal(JSON.parse(deniedByVendor.stdout).error, 'UPSTREAM_ERROR')
    assert.ok(!deniedByVendor.stdout.includes(accountKey))
    failure = 'redirect'
    const previousCalls = calls.length
    const redirect = await run(['info', '--profile', 'selected'])
    assert.equal(JSON.parse(redirect.stdout).error, 'UPSTREAM_ERROR')
    assert.ok(!redirect.stdout.includes(accountKey))
    assert.equal(calls.length, previousCalls + 1)
    failure = ''
    malformed = true
    const invalid = await run(['info', '--profile', 'selected'])
    assert.equal(invalid.code, 1)
    assert.equal(JSON.parse(invalid.stdout).error, 'INVALID_RESPONSE')
    await chmod(config, 0o666)
    const denied = await run(['auth', 'status', '--profile', 'selected'])
    assert.equal(JSON.parse(denied.stdout).error, 'CONFIG_INSECURE')
  } finally {
    await new Promise(resolve => server.close(resolve))
    await rm(root, { recursive: true, force: true })
  }
})
