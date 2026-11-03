import { readFile, writeFile } from 'node:fs/promises'
import { operations } from '../dist/catalogue.js'
import { description, nextSteps } from '../dist/discovery.js'

const target = new URL('../command-inventory.json', import.meta.url)
const commands = [
  ...operations.map(({ command, id, effect, cost, flags = [], argument }) => ({ command, operation: id, effect, cost,
    flags: ['--json', '--output', '--help', ...(id === 'OP-059' ? [] : ['--config', '--profile']),
      ...(['OP-039', 'OP-045'].includes(id) ? [] : ['--max-requests', '--max-bytes', '--timeout']),
      ...(cost === 'none' ? [] : ['--allow-operation', '--query-credit-budget']), ...(cost === 'unknown' ? ['--accept-unknown-cost'] : []), ...flags],
    arguments: argument ? [{ name: argument }] : [] })),
  ...['', 'doctor'].map(command => ({ command, operation: 'OP-045', effect: 'read', flags: ['--json', '--help', '--config', '--profile'], arguments: [] })),
  ...['auth status', 'profile list', 'config path'].map(command => ({ command, effect: 'read', flags: ['--json', '--help', '--config', '--profile'], arguments: [] })),
  { command: 'profile set', effect: 'local', flags: ['--json', '--help', '--config', '--env', '--file'], arguments: [{ name: 'name' }] },
  { command: 'init', effect: 'local', flags: ['--json', '--help', '--config', '--env', '--file'], arguments: [] },
]
const content = `${JSON.stringify({ commands }, null, 2)}\n`
const skill = `---\nname: shodan-axi\ndescription: Inspect Shodan account, host and DNS information using a configured SecretRef.\n---\n\n# Shodan investigation\n\n${description}.\n\n${nextSteps.map(step => `- \`${step}\``).join('\n')}\n\nUse \`--json\` for JSON output.\nConfigure a profile with \`shodan-axi profile set <name> --env <variable>\` or \`--file <absolute-path>\`; do not put a key on the command line.\nCredit-consuming reads require an exact operation grant and explicit budget.\n`
const skillPath = new URL('../skills/shodan-axi/SKILL.md', import.meta.url)
for (const [file, expected] of [[target, content], [skillPath, skill]]) {
  if (process.argv.includes('--write')) await writeFile(file, expected)
  else if (await readFile(file, 'utf8') !== expected) throw new Error(`Generated file is stale: ${file.pathname}`)
}
