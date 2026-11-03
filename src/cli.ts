import { encode } from '@toon-format/toon'
import { homedir } from 'node:os'
import { configPath, putProfile, readConfig, secret, select } from './credentials.js'
import { description, nextSteps } from './discovery.js'
import { ToolError } from './errors.js'
import { readPrivate } from './private-file.js'
import { read } from './vendor.js'

const usage = 'Commands: info, account profile, doctor, auth status, profile list, profile set, config path'
const help: Record<string, string> = {
  '': usage,
  info: 'info [--profile <name>] [--config <absolute-path>] [--json] - inspect plan and credits',
  'account profile': 'account profile [--profile <name>] [--config <absolute-path>] [--json] - inspect membership',
  doctor: 'doctor [--profile <name>] [--config <absolute-path>] [--json] - make one account information request',
  'auth status': 'auth status [--profile <name>] [--config <absolute-path>] [--json] - inspect the selected profile',
  'profile list': 'profile list [--config <absolute-path>] [--json] - list profiles',
  'profile set': 'profile set <name> (--env <variable> | --file <absolute-path>) [--config <absolute-path>] [--json]',
  init: 'init (--env <variable> | --file <absolute-path>) [--config <absolute-path>] [--json] - configure the default profile',
  'config path': 'config path [--config <absolute-path>] [--json] - show the config path',
}

function clean(value: unknown, key: string): unknown {
  if (typeof value === 'string') {
    const form = new URLSearchParams({ key }).toString().slice(4)
    return value.split(key).join('[REDACTED]').split(encodeURIComponent(key)).join('[REDACTED]').split(form).join('[REDACTED]').split(JSON.stringify(key).slice(1, -1)).join('[REDACTED]')
  }
  if (Array.isArray(value)) return value.map(item => clean(item, key))
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([field, item]) => [field, /(?:key|secret|token|password)/i.test(field) ? '[REDACTED]' : clean(item, key)]))
  return value
}

export async function main(args: string[]): Promise<void> {
  let key = ''
  let json = args.includes('--json')
  try {
    const flags = new Map<string, string | boolean>()
    const words: string[] = []
    for (let index = 0; index < args.length; index++) {
      const arg = args[index]
      if (!arg) continue
      if (!arg.startsWith('--')) { words.push(arg); continue }
      if (!['--json', '--help', '--config', '--profile', '--env', '--file'].includes(arg) || flags.has(arg)) {
        const flag = /^--[a-z][a-z0-9-]*$/.test(arg) ? arg : 'flag'
        throw new ToolError('INVALID_INPUT', `Unknown or repeated ${flag}`, 'Valid flags: --help, --json, --config, --profile; profile setup also accepts --env or --file')
      }
      if (arg === '--json' || arg === '--help') flags.set(arg, true)
      else {
        const value = args[++index]
        if (!value || value.startsWith('--')) throw new ToolError('INVALID_INPUT', `Missing value for ${arg}`, usage)
        flags.set(arg, value)
      }
    }
    json = flags.has('--json')
    const readOnly = process.env.SHODAN_AXI_READ_ONLY
    if (readOnly && !/^(?:true|false|1|0)$/i.test(readOnly)) throw new ToolError('CONFIG_INVALID', 'Invalid read-only setting', 'Set SHODAN_AXI_READ_ONLY to true or false')
    const option = (flag: string): string | undefined => { const value = flags.get(flag); return typeof value === 'string' ? value : undefined }
    const command = words.join(' ')
    const allowed = (words[0] === 'profile' && words[1] === 'set') || words[0] === 'init' ? ['--json', '--help', '--config', '--env', '--file'] : ['--json', '--help', '--config', '--profile']
    if ([...flags.keys()].some(flag => !allowed.includes(flag))) throw new ToolError('INVALID_INPUT', 'Flag is not available for this command', usage)
    if (flags.has('--help')) {
      const topic = words[0] === 'profile' && words[1] === 'set' && words.length <= 3 ? 'profile set' : command
      const text = help[topic]
      if (!text) throw new ToolError('INVALID_INPUT', 'Unknown command', usage)
      output({ command: topic || 'home', help: text }, json); return
    }
    const path = configPath(option('--config'))
    if (command === 'config path') { output({ path }, json); return }
    if (command === 'profile list') { output({ profiles: Object.keys((await readConfig(path)).profiles) }, json); return }
    if ((words[0] === 'profile' && words[1] === 'set' && words.length === 3) || command === 'init') {
      const env = option('--env'); const file = option('--file')
      const profileName = command === 'init' ? 'default' : words[2]
      if (Boolean(env) === Boolean(file) || !profileName) throw new ToolError('INVALID_INPUT', 'Supply exactly one SecretRef', 'Use profile set <name> --env <variable> or --file <absolute-path>')
      await putProfile(path, profileName, env ? { env } : { file }, command === 'init')
      output({ profile: profileName, status: 'configured' }, json); return
    }
    if (words[0] === 'init') throw new ToolError('INVALID_INPUT', 'Inline API keys are not accepted', 'Use init --env <variable> or --file <absolute-path>')
    if (!['', 'info', 'account profile', 'doctor', 'auth status'].includes(command)) throw new ToolError('INVALID_INPUT', 'Unknown command', usage)
    const selected = await select(path, option('--profile'), command === 'auth status' || command === 'doctor')
    if (command === 'auth status') {
      if (selected.profile.auth === 'api-key' && 'file' in selected.profile.apiKey) await readPrivate(selected.profile.apiKey.file, true, true)
      output({ profile: selected.name, source: selected.source, origin: selected.profile.origin, auth: selected.profile.auth, ...(selected.profile.auth === 'api-key' ? { apiKey: selected.profile.apiKey } : {}) }, json); return
    }
    key = await secret(selected, command === 'doctor')
    const result = await read(selected.profile.origin, command === 'account profile' ? '/account/profile' : '/api-info', key)
    if (!command) {
      const executable = process.argv[1] ?? 'shodan-axi'
      output(clean({ bin: executable.replace(homedir(), '~'), description, account: result, help: nextSteps }, key), json)
    } else if (command === 'doctor') output(clean({ status: 'ok', account: result }, key), json)
    else output(clean(result, key), json)
  } catch (error) {
    const failure = error instanceof ToolError ? error : new ToolError('CONFIG_INVALID', 'Unable to use configuration', 'Check profile settings and file permissions')
    output(clean({ error: failure.code, message: failure.message, help: failure.help }, key || '\u0000'), json)
    process.exitCode = failure.code === 'INVALID_INPUT' ? 2 : 1
  }
}

function output(value: unknown, json: boolean): void {
  process.stdout.write(`${json ? JSON.stringify(value) : encode(value)}\n`)
}
