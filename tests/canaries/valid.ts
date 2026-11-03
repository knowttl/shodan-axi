import type { Effect } from '../../src/contracts.js'
import type { ReadOperation } from '../../src/catalogue.js'
const effect: Effect = { kind: 'read' }
const operation: ReadOperation = { id: 'OP-001', command: 'example', path: '/', effect: 'read', cost: 'none', acceptance: 'AC-001' }
export { effect, operation }
