import { encode } from '@toon-format/toon'
import { homedir } from 'node:os'
import { z } from 'zod'
import { configPath, putProfile, readConfig, secret, select } from './credentials.js'
import { alertEvidence, validateAlertEvidence } from './alert-evidence.js'
import { description, nextSteps } from './discovery.js'
import { ToolError } from './errors.js'
import { evidence } from './evidence.js'
import { geonet } from './geonet.js'
import { investigate, planInvestigation } from './investigation.js'
import { draftClear, draftDomain, draftImport, draftMutation, isMutation, mutate, validateMutationFlags } from './mutations.js'
import { readPrivate } from './private-file.js'
import { clean } from './redact.js'
import { read } from './vendor.js'

const usage = 'Commands: info, account profile, doctor, auth status, profile list, profile set, init, config path, host, count, stats, search, search facets, search filters, search tokens, ports, domain, dns resolve, dns reverse, tools headers, myip, internetdb host, honeyscore, services, query list, query search, query tags, trends, trends filters, trends facets, exploits search, exploits count, alert info, alert list, alert triggers, alert create, alert update, alert remove, alert enable, alert disable, alert ignore, alert unignore, alert notifier add, alert notifier remove, alert clear, alert domain, alert import, alert export, alert stats, notifier list, notifier providers, notifier get, notifier create, notifier update, notifier remove, org info, org add, org remove, scan protocols, scan list, scan status, scan submit, scan internet, geonet ping, geonet geoping, geonet dns, geonet geodns, parse, convert'
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

export async function main(args: string[]): Promise<void> {
  let key = ''
  let json = args.includes('--json')
  try {
    const flags = new Map<string, string | boolean>()
    const words: string[] = []
    const aliases: Record<string, string> = { '-6': '--ipv6', '-H': '--history', '-T': '--type', '-D': '--details', '-S': '--save', '-O': '--filename', '-f': '--filters' }
    const booleanFlags = ['--json', '--help', '--history', '--details', '--save', '--full', '--color', '--no-color', '--ipv6', '--accept-unknown-cost', '--execute', '--silent', '--force']
    const valueFlags = ['--config', '--profile', '--env', '--file', '--output', '--page', '--offset', '--limit', '--max-pages', '--max-bytes', '--timeout', '--max-requests', '--query-credit-budget', '--scan-credit-budget', '--poll-attempts', '--poll-interval-ms', '--allow-operation', '--fields', '--filters', '--facets', '--type', '--minify', '--filename', '--format', '--separator', '--sort', '--order', '--size', '--expired', '--confirm', '--body-file', '--expires', '--vulns', '--triggers']
    for (let index = 0; index < args.length; index++) {
      const input = args[index]
      if (!input) continue
      const arg = aliases[input] ?? input
      if (!arg.startsWith('-')) { words.push(arg); continue }
      if (![...booleanFlags, ...valueFlags].includes(arg) || (flags.has(arg) && arg !== '--filters')) {
        const flag = /^--[a-z][a-z0-9-]*$/.test(arg) ? arg : 'flag'
        throw new ToolError('INVALID_INPUT', `Unknown or repeated ${flag}`, 'Valid flags: --help, --json, --config, --profile; profile setup also accepts --env or --file')
      }
      if (booleanFlags.includes(arg)) flags.set(arg, true)
      else {
        const value = args[++index]
        if (!value || value.startsWith('--')) throw new ToolError('INVALID_INPUT', `Missing value for ${arg}`, usage)
        if (arg === '--filters') {
          const previous = flags.get(arg)
          const filters = typeof previous === 'string' ? z.array(z.string()).parse(JSON.parse(previous)) : []
          flags.set(arg, JSON.stringify([...filters, value]))
        } else flags.set(arg, value)
      }
    }
    const outputFormat = flags.get('--output')
    if (outputFormat !== undefined && outputFormat !== 'json' && outputFormat !== 'toon') throw new ToolError('INVALID_INPUT', 'Unknown output format', 'Use --output json or --output toon')
    json = flags.has('--json') || outputFormat === 'json'
    const readOnly = process.env.SHODAN_AXI_READ_ONLY
    if (readOnly && !/^(?:true|false|1|0)$/i.test(readOnly)) throw new ToolError('CONFIG_INVALID', 'Invalid read-only setting', 'Set SHODAN_AXI_READ_ONLY to true or false')
    const option = (flag: string): string | undefined => { const value = flags.get(flag); return typeof value === 'string' ? value : undefined }
    const command = words.join(' ')
    if (words[0] === 'parse' || words[0] === 'convert') {
      const result = await evidence(words, flags)
      if (!json && result && typeof result === 'object' && 'display' in result && typeof result.display === 'string') process.stdout.write(`${result.display}\n`)
      else output(result, json)
      return
    }
    if (words[0] === 'alert' && ['stats', 'export'].includes(words[1] ?? '')) {
      validateAlertEvidence(words, flags)
      if (flags.has('--help')) { output({ command, help: 'Use --filename for a private output. Statistics use free count-facet reads with --facets, --limit and --max-requests; top-facet results are partial.' }, json); return }
      const selection = await select(configPath(option('--config')), option('--profile'))
      key = await secret(selection)
      output(clean(await alertEvidence(words, flags, selection, key), key), json)
      return
    }
    if (words[0] === 'geonet') {
      const result = await geonet(words, flags)
      if (result && typeof result === 'object' && 'error' in result) process.exitCode = 1
      output(result, json)
      return
    }
    if (isMutation(words)) {
      validateMutationFlags(flags)
      if (flags.has('--help')) { output({ command: words.slice(0, 2).join(' '), effect: 'write', cost: words[0] === 'scan' && words[1] === 'submit' ? 'scan' : 'unknown', help: words[0] === 'scan' ? 'Preview with --allow-operation, --scan-credit-budget and --max-requests; Internet scans also require --accept-unknown-cost. Repeat with --execute --confirm <token>.' : 'Preview with exact --allow-operation, --accept-unknown-cost, --query-credit-budget and --max-requests; repeat the request with --execute --confirm <token>.' }, json); return }
      const draft = ['clear', 'domain'].includes(words[1] ?? '') ? undefined : words[1] === 'import' ? await draftImport(words, flags) : await draftMutation(words, flags)
      const chosen = await select(configPath(option('--config')), option('--profile'))
      key = await secret(chosen)
      const selectedDraft = draft ?? await (words[1] === 'domain' ? draftDomain(words, flags, chosen, key) : draftClear(words, flags, chosen, key))
      const result = await mutate(selectedDraft, flags, chosen, key)
      if (typeof result === 'object' && result !== null && 'status' in result && (result.status === 'OUTCOME_UNKNOWN' || result.status === 'READBACK_UNVERIFIED')) process.exitCode = 1
      output(clean(result, key), json)
      return
    }
    const investigation = planInvestigation(words, flags)
    if (investigation) {
      if (flags.has('--help')) {
        output({ command: investigation.operation.command, operation: investigation.operation.id, effect: 'read', cost: investigation.operation.cost,
          argument: investigation.operation.argument ?? null, flags: investigation.operation.flags ?? [],
          defaults: { page: 1, maxPages: 1, maxRequests: 1, maxBytes: 1048576, timeoutMs: 30000, queryCreditBudget: 0 },
          example: `shodan-axi ${investigation.operation.command}${investigation.operation.argument ? ` <${investigation.operation.argument}>` : ''}${investigation.operation.cost === 'none' ? '' : ` --allow-operation ${investigation.operation.id} --query-credit-budget 1`}${investigation.operation.cost === 'unknown' ? ' --accept-unknown-cost --max-requests 1' : ''}`,
          help: 'Use explicit request and credit budgets when required.' }, json)
        return
      }
      if (investigation.operation.id === 'OP-059') {
        const result = await investigate(investigation, undefined, undefined)
        if (Buffer.byteLength(JSON.stringify(result)) > investigation.maxBytes) throw new ToolError('LIMIT_REACHED', 'Output exceeds the byte limit', 'Increase --max-bytes or narrow the selection')
        output(result, json); return
      }
      const chosen = await select(configPath(option('--config')), option('--profile'))
      key = await secret(chosen)
      if (investigation.operation.cost !== 'none') {
        const summary = clean({ operation: investigation.operation.id, query: investigation.argument ?? null, maxPages: investigation.maxPages,
          maxRequests: investigation.maxRequests, queryCreditBudget: investigation.queryBudget, cost: investigation.operation.cost }, key)
        process.stderr.write(`cost: ${JSON.stringify(summary)}\n`)
      }
      const result = clean(await investigate(investigation, chosen.profile.origin, key), key)
      if (Buffer.byteLength(JSON.stringify(result)) > investigation.maxBytes) throw new ToolError('LIMIT_REACHED', 'Output exceeds the byte limit', 'Increase --max-bytes or narrow the selection')
      if (!json && result && typeof result === 'object' && 'display' in result && typeof result.display === 'string') process.stdout.write(`${result.display}\n`)
      else output(result, json)
      return
    }
    const allowed = (words[0] === 'profile' && words[1] === 'set') || words[0] === 'init' ? ['--json', '--output', '--help', '--config', '--env', '--file'] : ['--json', '--output', '--help', '--config', '--profile']
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
    const selected = await select(path, option('--profile'))
    if (command === 'auth status') {
      if (selected.profile.auth === 'api-key' && 'file' in selected.profile.apiKey) await readPrivate(selected.profile.apiKey.file, true)
      output({ profile: selected.name, source: selected.source, origin: selected.profile.origin, auth: selected.profile.auth, ...(selected.profile.auth === 'api-key' ? { apiKey: selected.profile.apiKey } : {}) }, json); return
    }
    key = await secret(selected)
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
