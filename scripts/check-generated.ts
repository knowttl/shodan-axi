import { readFile, writeFile } from 'node:fs/promises'
import { operations } from '../dist/catalogue.js'
import type { ReadOperation } from '../dist/catalogue.js'
import { probes } from '../dist/geonet.js'
import { hostedWritePolicy } from '../dist/hosted-writes.js'
import { mutations } from '../dist/mutation-catalogue.js'
import { description, nextSteps } from '../dist/discovery.js'
import { hostedReadOutputs, statsOutput, homeOutput, doctorOutput, alertExportOutput, alertStatsOutput, dataListOutput } from '../dist/contracts.js'
import { z } from 'zod'

const target = new URL('../command-inventory.json', import.meta.url)
const commands = [
  { command: 'radar', operation: 'CLI-015', effect: 'stream', cost: 'unknown', flags: ['--json', '--output', '--help', '--config', '--profile', '--allow-operation', '--accept-unknown-cost', '--limit', '--max-bytes', '--timeout', '--idle-timeout', '--execute', '--confirm', '--filename', '--asn', '--countries', '--ports', '--vulns', '--custom-filters', '--alert', '--tags'], arguments: [] },
  { command: 'stream', operation: 'OP-046', effect: 'stream', cost: 'unknown', selectors: ['OP-047', 'OP-048', 'OP-049', 'OP-050', 'OP-051', 'OP-052', 'OP-053', 'OP-065'], flags: ['--json', '--output', '--help', '--config', '--profile', '--allow-operation', '--accept-unknown-cost', '--limit', '--max-bytes', '--timeout', '--idle-timeout', '--execute', '--confirm', '--follow', '--datadir', '--max-file-bytes', '--retain', '--compresslevel', '--fields', '--separator', '--color', '--no-color', '--quiet', '--asn', '--countries', '--ports', '--vulns', '--custom-filters', '--alert', '--tags'], arguments: [] },
  ...[{ command: 'threatnet events', operation: 'OP-067' }, { command: 'threatnet backscatter', operation: 'OP-068' }, { command: 'threatnet ssh', operation: 'OP-069' }].map(({ command, operation }) => ({ command, operation, effect: 'stream', cost: 'unknown', flags: ['--json', '--output', '--help', '--config', '--profile', '--allow-operation', '--accept-unknown-cost', '--limit', '--max-bytes', '--timeout', '--idle-timeout', '--execute', '--confirm', '--follow', '--datadir', '--max-file-bytes', '--retain', '--compresslevel'], arguments: [] })),
  { command: 'data list', operation: 'OP-034', selectors: ['OP-035'], effect: 'read', cost: 'none', flags: ['--json', '--output', '--help', '--config', '--profile', '--dataset'], arguments: [], outputSchema: z.toJSONSchema(dataListOutput) },
  { command: 'data download', operation: 'OP-071', effect: 'read', cost: 'unknown', flags: ['--json', '--output', '--help', '--config', '--profile', '--allow-operation', '--max-bytes', '--max-requests', '--filename', '--chunksize', '--resume', '--restart', '--execute', '--confirm'], arguments: [{ name: 'dataset' }, { name: 'name' }] },
  { command: 'download', operation: 'CLI-005', effect: 'read', cost: 'query', flags: ['--json', '--output', '--help', '--config', '--profile', '--allow-operation', '--query-credit-budget', '--max-requests', '--max-bytes', '--limit', '--filename', '--fields', '--execute', '--confirm'], arguments: [{ name: 'query' }] },
  { command: 'alert download', operation: 'CLI-020', effect: 'read', cost: 'query', flags: ['--json', '--output', '--help', '--config', '--profile', '--allow-operation', '--query-credit-budget', '--max-requests', '--max-bytes', '--limit', '--filename', '--fields', '--alert-id', '--execute', '--confirm'], arguments: [] },
  { command: 'parse', effect: 'local', flags: ['--json', '--output', '--help', '--fields', '--filters', '--filename', '--separator', '--color', '--no-color'], arguments: [{ name: 'file', variadic: true }] },
  { command: 'convert', effect: 'local', flags: ['--json', '--output', '--help', '--fields', '--filename'], arguments: [{ name: 'file' }, { name: 'format' }] },
  { command: 'alert export', operation: 'CLI-021', effect: 'read', cost: 'none', flags: ['--json', '--output', '--help', '--config', '--profile', '--filename', '--max-requests'], arguments: [], outputSchema: z.toJSONSchema(alertExportOutput) },
  { command: 'alert stats', operation: 'CLI-025', effect: 'read', cost: 'none', flags: ['--json', '--output', '--help', '--config', '--profile', '--filename', '--max-requests', '--facets', '--limit'], arguments: [], outputSchema: z.toJSONSchema(alertStatsOutput) },
  ...probes.map(({ command, id, argument }) => ({ command, operation: id, effect: 'active', cost: 'none', auth: 'none', flags: ['--json', '--output', '--help', '--allow-operation', '--max-requests', '--execute', '--confirm', ...(argument === 'hostname' ? ['--type'] : [])], arguments: [{ name: argument }] })),
  ...operations.map(({ command, id, effect, cost, flags = [], argument }: ReadOperation) => ({ command, operation: id, effect, cost,
    flags: ['--json', '--output', '--help', ...(id === 'OP-059' ? [] : ['--config', '--profile']),
      ...(['OP-039', 'OP-045'].includes(id) ? [] : ['--max-requests', '--max-bytes', '--timeout']),
      ...(cost === 'none' ? [] : ['--allow-operation', '--query-credit-budget']), ...(cost === 'unknown' ? ['--accept-unknown-cost'] : []), ...flags],
    arguments: argument ? [{ name: argument }] : [],
    ...(hostedReadOutputs[id] ? { outputSchema: z.toJSONSchema(command === 'stats' ? statsOutput : hostedReadOutputs[id]) } : {}) })),
  ...mutations.map(({ command, id, effect, cost, arguments: args }) => ({ command, operation: id, effect, cost,
    flags: ['--json', '--output', '--help', '--config', '--profile', '--allow-operation', ...(['OP-009', 'OP-010'].includes(id) ? ['--scan-credit-budget', '--query-credit-budget', '--wait', '--limit', '--max-bytes', '--idle-timeout', '--filename'] : ['--query-credit-budget']), '--max-requests', '--accept-unknown-cost', '--execute', '--confirm', ...(id === 'OP-009' ? ['--force', '--verbose'] : []), ...(id === 'OP-010' ? ['--quiet'] : []), ...(id === 'OP-013' ? ['--expires'] : []), ...(['OP-021', 'OP-070'].includes(id) ? ['--vulns'] : []), ...(['OP-027', 'OP-030'].includes(id) ? ['--body-file'] : []), ...(id === 'OP-037' ? ['--silent'] : [])],
    arguments: args.map(name => ({ name })) })),
  ...[{ command: 'alert clear', operation: 'CLI-017', args: [] }, { command: 'alert domain', operation: 'CLI-019', args: ['domain'] }, { command: 'alert import', operation: 'CLI-022', args: ['file'] }].map(({ command, operation, args }) => ({ command, operation, effect: 'write', cost: 'unknown',
    flags: ['--json', '--output', '--help', '--config', '--profile', '--allow-operation', '--query-credit-budget', '--max-requests', '--accept-unknown-cost', '--execute', '--confirm', ...(operation === 'CLI-019' ? ['--triggers'] : [])], arguments: args.map(name => ({ name })) })),
  ...['', 'doctor'].map(command => ({ command, operation: 'OP-045', effect: 'read', flags: ['--json', '--help', '--config', '--profile'], arguments: [], outputSchema: z.toJSONSchema(command ? doctorOutput : homeOutput) })),
  ...['auth status', 'profile list', 'config path'].map(command => ({ command, effect: 'read', flags: ['--json', '--help', '--config', '--profile'], arguments: [] })),
  { command: 'profile set', effect: 'local', flags: ['--json', '--help', '--config', '--env', '--file'], arguments: [{ name: 'name' }] },
  { command: 'init', effect: 'local', flags: ['--json', '--help', '--config', '--env', '--file'], arguments: [] },
  { command: 'setup', effect: 'local', flags: ['--json', '--output', '--help'], arguments: [{ name: 'target' }] },
  { command: 'skill', effect: 'local', flags: ['--json', '--output', '--help'], arguments: [] },
  { command: 'version', effect: 'local', flags: ['--help'], arguments: [] },
]
const content = `${JSON.stringify({ commands, hostedWrites: hostedWritePolicy }, null, 2)}\n`
const skill = `---\nname: shodan-axi\ndescription: Inspect Shodan account, host and DNS information using a configured SecretRef.\n---\n\n# Shodan investigation\n\n${description}.\n\n${nextSteps.map(step => `- \`${step}\``).join('\n')}\n\nUse \`--json\` for JSON output.\nConfigure a profile with \`shodan-axi profile set <name> --env <variable>\` or \`--file <absolute-path>\`; do not put a key on the command line.\nCredit-consuming reads require an exact operation grant and explicit budget.\n`
const skillPath = new URL('../skills/shodan-axi/SKILL.md', import.meta.url)
for (const [file, expected] of [[target, content], [skillPath, skill]] as const) {
  if (process.argv.includes('--write')) await writeFile(file, expected)
  else if (await readFile(file, 'utf8') !== expected) throw new Error(`Generated file is stale: ${file.pathname}`)
}
