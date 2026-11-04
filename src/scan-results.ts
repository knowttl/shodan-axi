import ipaddr from 'ipaddr.js'
import { z } from 'zod'

type Scope = { kind: 'targets'; networks: string[] } | { kind: 'port'; port: number }
const service = z.object({ ip_str: z.string(), port: z.number().int().min(1).max(65535), transport: z.string().min(1) }).passthrough()

export function collectScanEvents(scope: Scope, input: unknown[]): { events: z.output<typeof service>[]; duplicates: number; outOfScope: number } {
  const networks: [ipaddr.IPv4 | ipaddr.IPv6, number][] = scope.kind === 'targets' ? scope.networks.map(network => {
    if (network.includes('/')) return ipaddr.parseCIDR(network)
    const address = ipaddr.parse(network)
    return [address, address.kind() === 'ipv4' ? 32 : 128]
  }) : []
  const events: z.output<typeof service>[] = []; const seen = new Set<string>(); let duplicates = 0; let outOfScope = 0
  for (const value of input) {
    const parsed = service.safeParse(value)
    if (!parsed.success || !ipaddr.isValid(parsed.data.ip_str)) { outOfScope++; continue }
    const item = parsed.data; const address = ipaddr.parse(item.ip_str)
    const matches = scope.kind === 'port' ? item.port === scope.port : networks.some(([network, bits]) => network.kind() === address.kind() && address.match([network, bits]))
    if (!matches) { outOfScope++; continue }
    const identity = JSON.stringify([address.toNormalizedString(), item.port, item.transport.toLowerCase()])
    if (seen.has(identity)) { duplicates++; continue }
    seen.add(identity); events.push(item)
  }
  return { events, duplicates, outOfScope }
}
