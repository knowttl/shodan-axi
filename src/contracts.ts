import { z } from 'zod'

export type Effect = { kind: 'read' } | { kind: 'write'; operation: string; executeToken: string }

export const scanListItem = z.object({ id: z.string(), status: z.string(), created: z.string().optional(), status_check: z.string().optional(), credits_left: z.number().optional(), size: z.number().optional() })
export const scanJob = z.object({ id: z.string(), status: z.string(), count: z.number().int().nonnegative().optional(), created: z.string().optional() })

export const scanReadOutputs = {
  'OP-011': z.object({ items: z.array(scanListItem), total: z.number().int().nonnegative(), pagination: z.literal('undocumented'), complete: z.boolean() }),
  'OP-012': scanJob.extend({ polling: z.enum(['timeout', 'error', 'complete', 'attempt-limit']), error: z.string().optional() }),
}
