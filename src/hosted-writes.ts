import { isAbsolute } from 'node:path'
import type { Selection } from './credentials.js'
import { alertExportDraft, exportDraft, exportSearch } from './bulk-export.js'
import { ToolError } from './errors.js'
import { mutations } from './mutation-catalogue.js'
import { budgetCeiling, confirmationTtlMs, confirmedWrite, validateMutationFlags } from './mutations.js'

type Flags = Map<string, string | boolean>
export type WriteRequest = { words: string[]; flags: Flags; phase: 'preview' | 'execute'; confirmation?: string }

const approvedMutations = mutations.filter(mutation => !mutation.command.startsWith('scan '))
export const approvedWrites: readonly { command: string; operations: string[] }[] = [
  ...[...new Set(approvedMutations.map(mutation => mutation.command))].map(command => ({ command, operations: approvedMutations.filter(mutation => mutation.command === command).map(mutation => mutation.id) })),
  { command: 'alert clear', operations: ['OP-015'] },
  { command: 'alert domain', operations: ['OP-040', 'OP-013', 'OP-019'] },
  { command: 'alert import', operations: ['OP-027', 'OP-013', 'OP-019', 'OP-021', 'OP-023'] },
  { command: 'download', operations: ['OP-003'] },
  { command: 'alert download', operations: ['OP-003'] },
]
export const hostedWritePolicy = { approved: approvedWrites, budget: budgetCeiling, confirmation: { singleUse: true, ttlMs: confirmationTtlMs, boundTo: ['credential', 'profile', 'owner session', 'command', 'grants', 'budgets', 'observed state'] } }

const hostControlled = ['--config', '--profile', '--help', '--output', '--execute', '--confirm']

export async function hostedWrite(request: WriteRequest, credentials: () => Promise<{ selection: Selection; key: string }>, owner: string): Promise<unknown> {
  const text = request.words.join(' ')
  const approved = approvedWrites.filter(write => text === write.command || text.startsWith(`${write.command} `)).sort((a, b) => b.command.length - a.command.length)[0]
  if (!approved) throw new ToolError('INVALID_INPUT', 'This write is not approved for hosted execution', 'Use an approved write command')
  for (const flag of request.flags.keys()) if (hostControlled.includes(flag)) throw new ToolError('INVALID_INPUT', `Flag ${flag} is chosen by the host`, 'Remove the flag from the request')
  if ((request.phase === 'execute') !== (request.confirmation !== undefined)) throw new ToolError('INVALID_INPUT', 'Only execution carries a confirmation token', 'Send the token with the execute phase')
  const flags = new Map(request.flags)
  if (request.confirmation !== undefined) { flags.set('--execute', true); flags.set('--confirm', request.confirmation) }
  if (approved.operations.includes('OP-003')) {
    const destination = flags.get('--filename')
    if (typeof destination !== 'string' || !isAbsolute(destination)) throw new ToolError('INVALID_INPUT', 'An absolute destination is required', 'Provide the host-selected absolute destination')
    const { selection, key } = await credentials()
    const draft = approved.command === 'download' ? exportDraft(request.words, flags) : await alertExportDraft(request.words, flags, selection, key)
    return exportSearch(draft, flags, selection, key, owner)
  }
  validateMutationFlags(flags)
  return confirmedWrite(request.words, flags, credentials, owner)
}
