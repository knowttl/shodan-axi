export type MutationOperation = { readonly id: string; readonly command: string; readonly arguments: readonly string[]; readonly effect: 'write'; readonly cost: 'unknown'; readonly acceptance: string }

export const mutations = [
  { id: 'OP-013', command: 'alert create', arguments: ['name', 'targets'], effect: 'write', cost: 'unknown', acceptance: 'AC-013' },
  { id: 'OP-015', command: 'alert remove', arguments: ['id'], effect: 'write', cost: 'unknown', acceptance: 'AC-015' },
  { id: 'OP-016', command: 'alert update', arguments: ['id', 'targets'], effect: 'write', cost: 'unknown', acceptance: 'AC-016' },
  { id: 'OP-019', command: 'alert enable', arguments: ['id', 'trigger'], effect: 'write', cost: 'unknown', acceptance: 'AC-019' },
  { id: 'OP-020', command: 'alert disable', arguments: ['id', 'trigger'], effect: 'write', cost: 'unknown', acceptance: 'AC-020' },
  { id: 'OP-021', command: 'alert ignore', arguments: ['id', 'trigger', 'service'], effect: 'write', cost: 'unknown', acceptance: 'AC-021' },
  { id: 'OP-022', command: 'alert unignore', arguments: ['id', 'trigger', 'service'], effect: 'write', cost: 'unknown', acceptance: 'AC-022' },
  { id: 'OP-023', command: 'alert notifier add', arguments: ['id', 'notifier'], effect: 'write', cost: 'unknown', acceptance: 'AC-023' },
  { id: 'OP-024', command: 'alert notifier remove', arguments: ['id', 'notifier'], effect: 'write', cost: 'unknown', acceptance: 'AC-024' },
  { id: 'OP-027', command: 'notifier create', arguments: [], effect: 'write', cost: 'unknown', acceptance: 'AC-027' },
  { id: 'OP-028', command: 'notifier remove', arguments: ['id'], effect: 'write', cost: 'unknown', acceptance: 'AC-028' },
  { id: 'OP-030', command: 'notifier update', arguments: ['id'], effect: 'write', cost: 'unknown', acceptance: 'AC-030' },
  { id: 'OP-037', command: 'org add', arguments: ['user'], effect: 'write', cost: 'unknown', acceptance: 'AC-037' },
  { id: 'OP-038', command: 'org remove', arguments: ['user'], effect: 'write', cost: 'unknown', acceptance: 'AC-038' },
  { id: 'OP-070', command: 'alert ignore', arguments: ['id', 'trigger', 'service'], effect: 'write', cost: 'unknown', acceptance: 'AC-070' },
] as const satisfies readonly MutationOperation[]
