import type { Effect } from '../../src/contracts.js'
export const read: Effect = { kind: 'read', executeToken: 'not-allowed' }
export const write: Effect = { kind: 'write', executeToken: 'token' }
