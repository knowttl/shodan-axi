import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import test from 'node:test'

for (const target of ['claude', 'codex', 'opencode']) {
  test(`setup ${target} is explicit and idempotent`, async () => {
    const home = await mkdtemp(join(tmpdir(), 'shodan-setup-'))
    try {
      const env = { ...process.env, HOME: home, USERPROFILE: home, CLAUDE_CONFIG_DIR: join(home, 'claude'), CODEX_HOME: join(home, 'codex'), XDG_CONFIG_HOME: join(home, 'config') }
      const invoke = (...args) => JSON.parse(execFileSync(process.execPath, [resolve('bin/shodan-axi.js'), ...args, '--json'], { env, encoding: 'utf8' }))
      invoke('--help')
      assert.deepEqual(await readdir(home), [])
      assert.equal(invoke('setup', target).changed, true)
      assert.deepEqual(await readdir(home), [target === 'opencode' ? 'config' : target])
      assert.equal(invoke('setup', target).changed, false)
      if (target === 'codex') assert.match(await readFile(join(home, 'codex', 'config.toml'), 'utf8'), /hooks = true/)
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
  const home = await mkdtemp(join(tmpdir(), 'shodan-setup-'))
  try {
    await mkdir(join(home, 'codex'))
    await writeFile(join(home, 'codex', 'config.toml'), '[features]\nother = true\nhooks = false\n\n[other]\nvalue = 1\n')
    await writeFile(join(home, 'codex', 'hooks.json'), JSON.stringify({ hooks: { SessionStart: [{ hooks: [{ type: 'command', command: 'other-command' }] }] } }))
    const env = { ...process.env, CODEX_HOME: join(home, 'codex') }
    execFileSync(process.execPath, [resolve('bin/shodan-axi.js'), 'setup', 'codex'], { env })
    assert.equal(await readFile(join(home, 'codex', 'config.toml'), 'utf8'), '[features]\nother = true\nhooks = true\n\n[other]\nvalue = 1\n')
    const hooks = JSON.parse(await readFile(join(home, 'codex', 'hooks.json'), 'utf8'))
    assert.equal(hooks.hooks.SessionStart[0].hooks[0].command, 'other-command')
    assert.equal(hooks.hooks.SessionStart.length, 2)
  } finally { await rm(home, { recursive: true, force: true }) }
})
