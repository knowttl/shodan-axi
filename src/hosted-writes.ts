import { isAbsolute } from 'node:path'
import type { Selection } from './credentials.js'
import { alertExportDraft, exportBudgetPolicy, exportBudgetRules, exportDraft, exportSearch } from './bulk-export.js'
import { ToolError } from './errors.js'
import { mutations } from './mutation-catalogue.js'
import { budgetCeiling, budgetRules, confirmationTtlMs, confirmedWrite, domainBudgetRules, draftClear, draftImport, draftMutation, mutationBudgetPolicy, validateMutationFlags } from './mutations.js'

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
export const hostedWritePolicy = { approved: approvedWrites, budget: budgetCeiling, budgetRules: Object.fromEntries(approvedWrites.map(({ command }) => [command, command === 'download' || command === 'alert download' ? { kind: command, ...exportBudgetPolicy } : { kind: 'mutation', ...(command === 'alert clear' ? mutationBudgetPolicy.clear : command === 'alert domain' ? mutationBudgetPolicy.domain : mutationBudgetPolicy.ordinary), ...(command === 'alert domain' ? { preflight: mutationBudgetPolicy.domainPreflight } : {}) }])), confirmation: { singleUse: true, ttlMs: confirmationTtlMs, boundTo: ['credential', 'profile', 'owner session', 'command', 'grants', 'budgets', 'observed state'] } }

const hostControlled = ['--config', '--profile', '--help', '--output', '--execute', '--confirm']

function approvedWrite(words: string[]): typeof approvedWrites[number] {
  const text = words.join(' ')
  const approved = approvedWrites.filter(write => text === write.command || text.startsWith(`${write.command} `)).sort((a, b) => b.command.length - a.command.length)[0]
  if (!approved) throw new ToolError('INVALID_INPUT', 'This write is not approved for hosted execution', 'Use an approved write command')
  return approved
}

export async function hostedWriteBudget(words: string[], input: Flags, credentials: () => Promise<{ selection: Selection; key: string }>): Promise<ReturnType<typeof budgetRules> & { preflight?: { minimumCredit: number; minimumRequests: number } }> {
  const approved = approvedWrite(words)
  for (const flag of input.keys()) if (hostControlled.includes(flag)) throw new ToolError('INVALID_INPUT', `Flag ${flag} is chosen by the host`, 'Remove the flag from the request')
  if (approved.command === 'alert domain') return domainBudgetRules(words, input)
  const flags = new Map(input)
  flags.set('--max-requests', String(budgetCeiling.requests))
  if (approved.operations.includes('OP-003')) {
    if (!flags.has('--query-credit-budget')) flags.set('--query-credit-budget', String(Math.ceil(Number(flags.get('--limit')) / exportBudgetPolicy.resultsPerCredit)))
    const draft = approved.command === 'download' ? exportDraft(words, flags, false) : await (async () => { const { selection, key } = await credentials(); return alertExportDraft(words, flags, selection, key, false) })()
    return exportBudgetRules(draft)
  }
  validateMutationFlags(flags)
  let draft
  if (approved.command === 'alert clear') {
    flags.set('--query-credit-budget', String(budgetCeiling.queryCredits))
    const { selection, key } = await credentials()
    draft = await draftClear(words, flags, selection, key)
  } else draft = await (approved.command === 'alert import' ? draftImport(words, flags) : draftMutation(words, flags))
  return budgetRules(draft)
}

export async function hostedWrite(request: WriteRequest, credentials: () => Promise<{ selection: Selection; key: string }>, owner: string): Promise<unknown> {
  const approved = approvedWrite(request.words)
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
