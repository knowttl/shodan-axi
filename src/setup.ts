import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { z } from 'zod'
import { ToolError } from './errors.js'

async function readOptional(path: string): Promise<string> {
  try { return await readFile(path, 'utf8') } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return ''
    throw error
  }
}

async function save(path: string, content: string): Promise<boolean> {
  if (await readOptional(path) === content) return false
  await mkdir(dirname(path), { recursive: true })
  await writeFile(path, content)
  return true
}

export async function setup(target: string): Promise<{ target: string, changed: boolean }> {
  if (!['claude', 'codex', 'opencode'].includes(target)) throw new ToolError('INVALID_INPUT', 'Choose a setup target', 'Use setup claude, setup codex or setup opencode')
  const executable = resolve(process.argv[1] ?? '')
  const quote = (value: string): string => process.platform === 'win32' ? `"${value.replaceAll('"', '\\"')}"` : `'${value.replaceAll("'", "'\\''")}'`
  const command = `${quote(process.execPath)} ${quote(executable)} auth status --json`
  if (target === 'opencode') {
    const root = process.env.XDG_CONFIG_HOME || join(homedir(), '.config')
    const path = join(root, 'opencode', 'plugins', 'shodan-axi.js')
    const content = `import { execFileSync } from 'node:child_process'\nexport const ShodanAxi = async () => ({\n  'experimental.chat.system.transform': async (_input, output) => {\n    try { output.system.push(execFileSync(${JSON.stringify(process.execPath)}, [${JSON.stringify(executable)}, 'auth', 'status'], { encoding: 'utf8' })) } catch {}\n  },\n})\n`
    return { target, changed: await save(path, content) }
  }
  const root = target === 'claude' ? (process.env.CLAUDE_CONFIG_DIR || join(homedir(), '.claude')) : (process.env.CODEX_HOME || join(homedir(), '.codex'))
  const path = join(root, target === 'claude' ? 'settings.json' : 'hooks.json')
  const original = await readOptional(path)
  const settings = z.looseObject({ hooks: z.record(z.string(), z.unknown()).optional() }).parse(original ? JSON.parse(original) : {})
  const hooks = settings.hooks ?? {}
  const entries = z.array(z.looseObject({ hooks: z.array(z.looseObject({ command: z.string().optional() })).optional() })).parse(hooks.SessionStart ?? [])
  const retained = entries.flatMap(entry => {
    if (!entry.hooks) return [entry]
    const remaining = entry.hooks.filter(hook => !(hook.command?.includes('shodan-axi') && hook.command.endsWith(' auth status --json')))
    return remaining.length ? [{ ...entry, hooks: remaining }] : []
  })
  retained.push({ hooks: [{ type: 'command', command }] })
  hooks.SessionStart = retained
  settings.hooks = hooks
  let changed = await save(path, `${JSON.stringify(settings, null, 2)}\n`)
  if (target === 'codex') {
    const configPath = join(root, 'config.toml')
    const config = await readOptional(configPath)
    const section = /^\[features\][^\n]*(?:\n|$)(?:(?![ \t]*\[)[^\n]*(?:\n|$))*/m.exec(config)
    let updated: string
    if (!section) updated = `${config}${config && !config.endsWith('\n') ? '\n' : ''}\n[features]\nhooks = true\n`
    else {
      const value = /^[ \t]*hooks[ \t]*=.*$/m
      const replacement = value.test(section[0]) ? section[0].replace(value, 'hooks = true') : `${section[0].replace(/\n?$/, '\n')}hooks = true\n`
      updated = config.replace(section[0], replacement)
    }
    changed = await save(configPath, updated) || changed
  }
  return { target, changed }
}
