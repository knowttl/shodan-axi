export type Effect = { kind: 'read' } | { kind: 'write'; operation: string; executeToken: string }
