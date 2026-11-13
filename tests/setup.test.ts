import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import test from 'node:test'
import { getStaticTOMLValue, parseTOML } from 'toml-eslint-parser'

for (const target of ['claude', 'codex', 'opencode']) {
  test(`setup ${target} is explicit and idempotent`, async () => {
    const home = await mkdtemp(resolve('shodan-setup-'))
    try {
      const env = { ...process.env, HOME: home, USERPROFILE: home, CLAUDE_CONFIG_DIR: join(home, 'claude'), CODEX_HOME: join(home, 'codex'), XDG_CONFIG_HOME: join(home, 'config') }
      const invoke = (...args: string[]) => JSON.parse(execFileSync(process.execPath, [resolve('bin/shodan-axi.js'), ...args, '--json'], { env, encoding: 'utf8' }))
      invoke('--help')
      assert.deepEqual(await readdir(home), [])
      assert.equal(invoke('setup', target).changed, true)
      assert.deepEqual(await readdir(home), [target === 'opencode' ? 'config' : target])
      assert.equal(invoke('setup', target).changed, false)
      if (target === 'codex') assert.equal((getStaticTOMLValue(parseTOML(await readFile(join(home, 'codex', 'config.toml'), 'utf8'))) as { features: { hooks: boolean } }).features.hooks, true)
    } finally { await rm(home, { recursive: true, force: true }) }
  })
}

test('skill command prints the generated skill', async () => {
  const skill = await readFile(resolve('skills/shodan-axi/SKILL.md'), 'utf8')
  assert.equal(execFileSync(process.execPath, [resolve('bin/shodan-axi.js'), 'skill'], { encoding: 'utf8' }), skill)
})

test('version help is available offline', () => {
  const result = JSON.parse(execFileSync(process.execPath, [resolve('bin/shodan-axi.js'), 'version', '--help', '--json'], { encoding: 'utf8' }))
  assert.match(result.help, /packaged version/)
})

test('setup preserves other Codex configuration and hooks', async () => {
  const home = await mkdtemp(resolve('shodan-setup-'))
  try {
    await mkdir(join(home, 'codex'))
    await writeFile(join(home, 'codex', 'config.toml'), '[features]\nother = true\nhooks = false\n\n[other]\nvalue = 1\n')
    await writeFile(join(home, 'codex', 'hooks.json'), JSON.stringify({ hooks: { SessionStart: [{ hooks: [{ type: 'command', command: 'other-command' }] }] } }))
    const env = { ...process.env, CODEX_HOME: join(home, 'codex') }
    execFileSync(process.execPath, [resolve('bin/shodan-axi.js'), 'setup', 'codex'], { env })
    assert.deepEqual(getStaticTOMLValue(parseTOML(await readFile(join(home, 'codex', 'config.toml'), 'utf8'))), { features: { other: true, hooks: true }, other: { value: 1 } })
    const hooks = JSON.parse(await readFile(join(home, 'codex', 'hooks.json'), 'utf8'))
    assert.equal(hooks.hooks.SessionStart[0].hooks[0].command, 'other-command')
    assert.equal(hooks.hooks.SessionStart.length, 2)
  } finally { await rm(home, { recursive: true, force: true }) }
})

for (const [name, config, expected] of [
  ['indented table', ' [features]\nother = true\nhooks = false\n', { features: { other: true, hooks: true } }],
  ['quoted key', '[features]\n"hooks" = false\n', { features: { hooks: true } }],
  ['quoted table and literal key', "[ 'features' ] # keep\n'hooks' = false # keep\n", { features: { hooks: true } }],
  ['escaped keys', '["feat\\u0075res"]\n"h\\u006foks" = false\n', { features: { hooks: true } }],
  ['commented setting', '[features]\n# hooks = true\nhooks = false\n', { features: { hooks: true } }],
  ['missing setting', '[features]\nother = true\n[other]\nvalue = 1\n', { features: { other: true, hooks: true }, other: { value: 1 } }],
  ['header at EOF', '[features] # keep', { features: { hooks: true } }],
  ['CRLF', '[features]\r\nhooks = false\r\n', { features: { hooks: true } }],
  ['dotted setting', 'features.hooks = false\nfeatures.other = true\n', { features: { hooks: true, other: true } }],
  ['dotted sibling', 'features.other = true\n', { features: { hooks: true, other: true } }],
  ['inline setting', 'features = { hooks = false, other = true }\n', { features: { hooks: true, other: true } }],
  ['inline missing setting', 'features = { other = true }\n', { features: { hooks: true, other: true } }],
  ['inline empty table', 'features = {}\n', { features: { hooks: true } }],
  ['implicit features table', '[features.other]\nvalue = 1\n', { features: { hooks: true, other: { value: 1 } } }],
  ['unrelated table', '[other]\nhooks = false\n', { features: { hooks: true }, other: { hooks: false } }],
  ['multiline decoy', 'text = """\n[features]\nhooks = false\n"""\n', { features: { hooks: true }, text: '[features]\nhooks = false\n' }],
] satisfies [unknown, ...unknown[]][]) {
  test(`setup codex enables hooks and preserves settings with ${name}`, async () => {
    const home = await mkdtemp(resolve('shodan-setup-'))
    try {
      const configPath = join(home, 'config.toml')
      await writeFile(configPath, config)
      const env = { ...process.env, CODEX_HOME: home }
      const invoke = () => JSON.parse(execFileSync(process.execPath, [resolve('bin/shodan-axi.js'), 'setup', 'codex', '--json'], { env, encoding: 'utf8' }))
      assert.equal(invoke().changed, true)
      assert.deepEqual(getStaticTOMLValue(parseTOML(await readFile(configPath, 'utf8'))), expected)
      assert.equal(invoke().changed, false)
    } finally { await rm(home, { recursive: true, force: true }) }
  })
}

test('setup codex preserves enabled configuration bytes including comments', async () => {
  const home = await mkdtemp(resolve('shodan-setup-'))
  try {
    const config = ' # keep\r\n[ "features" ]\r\n"hooks" = true # keep\r\n'
    const configPath = join(home, 'config.toml')
    await writeFile(configPath, config)
    execFileSync(process.execPath, [resolve('bin/shodan-axi.js'), 'setup', 'codex'], { env: { ...process.env, CODEX_HOME: home } })
    assert.equal(await readFile(configPath, 'utf8'), config)
  } finally { await rm(home, { recursive: true, force: true }) }
})

test('setup codex changes only the disabled boolean bytes', async () => {
  const home = await mkdtemp(resolve('shodan-setup-'))
  try {
    const configPath = join(home, 'config.toml')
    await writeFile(configPath, 'text = """\n[features]\nhooks = false\n"""\n ["features"] # keep\n"hooks" = false # keep false\nother = true\n')
    execFileSync(process.execPath, [resolve('bin/shodan-axi.js'), 'setup', 'codex'], { env: { ...process.env, CODEX_HOME: home } })
    assert.equal(await readFile(configPath, 'utf8'), 'text = """\n[features]\nhooks = false\n"""\n ["features"] # keep\n"hooks" = true # keep false\nother = true\n')
  } finally { await rm(home, { recursive: true, force: true }) }
})

for (const [name, config] of [
  ['invalid TOML', '[features\n'],
  ['duplicate keys', '[features]\nhooks = false\n"hooks" = true\n'],
  ['scalar features', 'features = false\n'],
  ['array features', '[[features]]\nhooks = false\n'],
  ['nonboolean hooks', '[features]\nhooks = "false"\n'],
  ['table hooks', '[features.hooks]\nvalue = false\n'],
] satisfies [unknown, ...unknown[]][]) {
  test(`setup codex rejects ${name} before changing either file`, async () => {
    const home = await mkdtemp(resolve('shodan-setup-'))
    try {
      const configPath = join(home, 'config.toml')
      const hooksPath = join(home, 'hooks.json')
      const hooks = '{"hooks":{"SessionStart":[]}}\n'
      await writeFile(configPath, config)
      await writeFile(hooksPath, hooks)
      assert.throws(() => execFileSync(process.execPath, [resolve('bin/shodan-axi.js'), 'setup', 'codex', '--json'], { env: { ...process.env, CODEX_HOME: home }, encoding: 'utf8' }), error => {
        assert.equal(JSON.parse((error as { stdout: string }).stdout).error, 'INVALID_INPUT')
        return true
      })
      assert.equal(await readFile(configPath, 'utf8'), config)
      assert.equal(await readFile(hooksPath, 'utf8'), hooks)
    } finally { await rm(home, { recursive: true, force: true }) }
  })
}
