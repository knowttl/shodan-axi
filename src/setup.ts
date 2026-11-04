import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { getStaticTOMLValue, parseTOML } from 'toml-eslint-parser'
import type { AST } from 'toml-eslint-parser'
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

function enableCodexHooks(config: string): string {
  try {
    const ast = parseTOML(config, { tomlVersion: '1.0' })
    const settings = z.looseObject({ features: z.looseObject({ hooks: z.boolean().optional() }).optional() }).parse(getStaticTOMLValue(ast))
    if (settings.features?.hooks === true) return config
    const body = ast.body[0].body
    const table = body.find((node): node is AST.TOMLTable => node.type === 'TOMLTable' && node.kind === 'standard' && node.resolvedKey.length === 1 && node.resolvedKey[0] === 'features')
    const entries = body.filter((node): node is AST.TOMLKeyValue => node.type === 'TOMLKeyValue')
    const find = (entries: AST.TOMLKeyValue[], path: string[]): AST.TOMLKeyValue | undefined => {
      for (const entry of entries) {
        const keys = getStaticTOMLValue(entry.key)
        if (!keys.every((key, index) => key === path[index])) continue
        if (keys.length === path.length) return entry
        if (entry.value.type === 'TOMLInlineTable') {
          const nested = find(entry.value.body, path.slice(keys.length))
          if (nested) return nested
        }
      }
    }
    const hook = find(entries, ['features', 'hooks']) ?? find(table?.body ?? [], ['hooks'])
    const features = find(entries, ['features'])
    let updated: string
    if (hook) updated = `${config.slice(0, hook.value.range[0])}true${config.slice(hook.value.range[1])}`
    else if (features?.value.type === 'TOMLInlineTable') {
      const end = features.value.range[1] - 1
      updated = `${config.slice(0, end)}${features.value.body.length ? ', ' : ''}hooks = true${config.slice(end)}`
    } else if (table) {
      const end = config.indexOf('\n', table.key.range[1])
      updated = end === -1 ? `${config}\nhooks = true\n` : `${config.slice(0, end + 1)}hooks = true\n${config.slice(end + 1)}`
    } else updated = `features.hooks = true\n${config}`
    parseTOML(updated, { tomlVersion: '1.0' })
    return updated
  } catch {
    throw new ToolError('INVALID_INPUT', 'Cannot safely enable Codex hooks in config.toml', 'Use valid TOML with a features table and a boolean hooks setting, then retry setup codex')
  }
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
  let configPath: string | undefined
  let updated: string | undefined
  if (target === 'codex') {
    configPath = join(root, 'config.toml')
    updated = enableCodexHooks(await readOptional(configPath))
  }
  let changed = await save(path, `${JSON.stringify(settings, null, 2)}\n`)
  if (configPath !== undefined && updated !== undefined) changed = await save(configPath, updated) || changed
  return { target, changed }
}
