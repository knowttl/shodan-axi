export type ReadOperation = { readonly id: string; readonly command: string; readonly path: string; readonly effect: 'read'; readonly cost: 'none'; readonly acceptance: string }

export const operations = [
  { id: 'OP-039', command: 'account profile', path: '/account/profile', effect: 'read', cost: 'none', acceptance: 'AC-039' },
  { id: 'OP-045', command: 'info', path: '/api-info', effect: 'read', cost: 'none', acceptance: 'AC-045' },
] as const satisfies readonly ReadOperation[]
