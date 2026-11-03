export type Effect = { kind: 'read' } | { kind: 'write'; operation: string; executeToken: string }
export type Pagination = { kind: 'none' } | { kind: 'page'; next: number }
export type StreamState = { kind: 'open' } | { kind: 'closed'; reason: string }
export type Cost = { kind: 'known'; amount: number } | { kind: 'unknown' }
export type WriteOutcome = { kind: 'complete' } | { kind: 'unknown'; reason: string }
