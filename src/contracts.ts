import { z } from 'zod'

export type Effect = { kind: 'read' } | { kind: 'write'; operation: string; executeToken: string }

export const info = z.object({ plan: z.string(), query_credits: z.number(), scan_credits: z.number(), monitored_ips: z.number(), usage_limits: z.object({ query_credits: z.number(), scan_credits: z.number(), monitored_ips: z.number() }) })
export const account = z.object({ member: z.boolean(), credits: z.number(), display_name: z.string().nullable(), created: z.string() })
export const banner = z.object({ ip_str: z.string(), port: z.number().int(), transport: z.string(), timestamp: z.string(),
  data: z.string().optional(), hostnames: z.array(z.string()).optional(), domains: z.array(z.string()).optional(),
  org: z.string().optional(), isp: z.string().optional(), asn: z.string().optional(), product: z.string().optional(), version: z.string().optional(),
  location: z.object({ country_code: z.string().nullable().optional(), country_name: z.string().nullable().optional(), city: z.string().nullable().optional(), latitude: z.number().nullable().optional(), longitude: z.number().nullable().optional() }).optional(),
  ssl: z.object({ cert: z.object({ pubkey: z.object({ bits: z.number(), type: z.string() }).optional() }).optional() }).optional(),
  metadata: z.object({ truncated: z.array(z.string()).optional() }).optional(),
})
export const host = z.object({ ip_str: z.string(), ports: z.array(z.number().int()), data: z.array(banner),
  hostnames: z.array(z.string()).optional(), domains: z.array(z.string()).optional(), tags: z.array(z.string()).optional(),
  org: z.string().optional(), isp: z.string().optional(), asn: z.string().optional(), last_update: z.string().optional(),
  country_code: z.string().nullable().optional(), country_name: z.string().nullable().optional(), city: z.string().nullable().optional(),
  latitude: z.number().nullable().optional(), longitude: z.number().nullable().optional(),
})
const facet = z.object({ value: z.union([z.string(), z.number()]), count: z.number().int().nonnegative() })
export const facets = z.object(Object.fromEntries(['port', 'country', 'country_name', 'city', 'org', 'asn', 'domain', 'isp', 'os', 'product', 'version', 'http.title', 'http.component', 'ssl.version', 'ssl.cert.subject.cn', 'ssl.cert.pubkey.bits', 'key', 'vuln', 'vuln.verified', 'tag'].map(name => [name, z.array(facet).optional()])))
export const count = z.object({ total: z.number().int().nonnegative(), facets: facets.optional() })
export const tokenized = z.object({ attributes: z.object({ ports: z.array(z.number()).optional(), hostnames: z.array(z.string()).optional(), ips: z.array(z.string()).optional(), countries: z.array(z.string()).optional(), domains: z.array(z.string()).optional(), asns: z.array(z.string()).optional() }), errors: z.array(z.string()), string: z.string(), filters: z.array(z.string()) })
export const internetdb = z.object({ ip: z.string(), ports: z.array(z.number().int()), cpes: z.array(z.string()), hostnames: z.array(z.string()), tags: z.array(z.string()), vulns: z.array(z.string()) })
export const protocols = z.object(Object.fromEntries([
  'afp', 'ajp', 'amqp', 'andromouse', 'apple-airport-admin', 'ard', 'bacnet', 'bgp', 'cassandra', 'checkpoint', 'coap', 'codesys', 'couchdb', 'dahua-dvr', 'db2', 'dnp3', 'dns-udp', 'docker', 'elasticsearch', 'epmd', 'ethernetip', 'fox', 'ftp', 'ftp-ssl', 'gopher', 'hart-ip', 'hbase', 'http', 'http-simple-new', 'https', 'https-simple-new', 'icap', 'iec-104', 'ike', 'imap', 'imap-ssl', 'ipmi', 'ipp', 'iscsi', 'knx', 'ldap', 'ldap-ssl', 'memcached', 'mikrotik-routeros', 'modbus', 'mongodb', 'mqtt', 'ms-sql', 'mysql', 'netbios', 'nntp', 'ntp', 'opc-ua', 'openvpn', 'oracle', 'pcworx', 'pop3', 'pop3-ssl', 'postgresql', 'pptp', 'qconn', 'rdp', 'redis', 'rethinkdb', 'rlogin', 'rsync', 'rtsp', 's7', 'samsung-dvr', 'sip', 'smb', 'smtp', 'smtp-ssl', 'snmp', 'socks', 'ssh', 'steam-a2s', 'telnet', 'tftp', 'tls', 'tor-requests', 'ubiquiti-discover', 'upnp', 'ventrilo', 'vnc', 'weblogic-t3', 'ws-discovery', 'x11', 'zookeeper',
].map(name => [name, z.string().optional()])))
export const headers = z.object(Object.fromEntries(['Accept', 'Accept-Encoding', 'Accept-Language', 'Connection', 'Host', 'User-Agent', 'Via', 'X-Forwarded-For', 'X-Forwarded-Proto', 'X-Real-IP'].map(name => [name, z.string().optional()])))
export const alert = z.object({ id: z.string(), name: z.string(), filters: z.object({ ip: z.array(z.string()) }),
  created: z.string().optional(), expiration: z.string().nullable().optional(), size: z.number().optional(),
  notifiers: z.array(z.string()).optional(),
  triggers: z.object(Object.fromEntries(['any', 'new_service', 'open_database', 'industrial_control_system', 'vulnerable', 'malware', 'ssl_expired', 'ssl_self_signed', 'uncommon', 'uncommon_plus', 'vulnerable_unverified', 'internet_scanner'].map(name => [name, z.object({}).optional()]))).optional(),
})
export const trigger = z.object({ name: z.string(), rule: z.string(), description: z.string() })
export const notifier = z.object({ id: z.string(), provider: z.string(), description: z.string().optional() })
export const providers = z.object(Object.fromEntries(['email', 'telegram', 'webhook', 'slack', 'gitter', 'pagerduty', 'phone', 'pushover'].map(name => [name, z.object({ required: z.array(z.string()), description: z.string().optional() }).optional()])))
const member = z.object({ username: z.string(), email: z.string() })
export const organization = z.object({ id: z.string(), name: z.string(), created: z.string().optional(), admins: z.array(member), members: z.array(member), upgrade_type: z.string().optional(), domains: z.array(z.string()), logo: z.boolean() })
export const directoryQuery = z.object({ title: z.string(), query: z.string(), votes: z.number().optional(), description: z.string().optional(), timestamp: z.string().optional(), tags: z.array(z.string()).optional() })
export const directoryTag = z.object({ value: z.string(), count: z.number().int().nonnegative() })

export const scanListItem = z.object({ id: z.string(), status: z.string(), created: z.string().optional(), status_check: z.string().optional(), credits_left: z.number().optional(), size: z.number().optional() })
export const scanJob = z.object({ id: z.string(), status: z.string(), count: z.number().int().nonnegative().optional(), created: z.string().optional() })

export const scanReadOutputs = {
  'OP-011': z.object({ items: z.array(scanListItem), total: z.number().int().nonnegative(), pagination: z.literal('undocumented'), complete: z.boolean() }),
  'OP-012': scanJob.extend({ polling: z.enum(['timeout', 'error', 'complete', 'attempt-limit']), error: z.string().optional() }),
}

const strings = z.object({ items: z.array(z.string()), count: z.number().int().nonnegative() })
const directory = z.object({ items: z.array(directoryQuery), count: z.number().int().nonnegative(), total: z.number().int().nonnegative(), page: z.number().int(), complete: z.boolean() })
const artifact = z.object({ path: z.string(), appendedBytes: z.number().int(), appendedSha256: z.string() })
const address = z.object({ ip: z.string(), addressFamily: z.union([z.literal(4), z.literal(6)]), attribution: z.literal('egress address of execution location') })
export const hostedReadOutputs: Record<string, z.ZodType> = {
  ...scanReadOutputs,
  'OP-039': account, 'OP-045': info,
  'OP-001': z.object({ host, banners: z.array(banner), historyRequested: z.boolean(), vendorTruncations: z.array(z.string()).optional(), fullHistoricalPayload: z.literal(false).optional(), display: z.string().optional(), saved: artifact.optional() }),
  'OP-002': count,
  'OP-004': strings, 'OP-005': strings, 'OP-006': tokenized,
  'OP-007': z.object({ items: z.array(z.number().int()), count: z.number().int().nonnegative() }),
  'OP-008': protocols,
  'OP-014': alert, 'OP-017': z.object({ items: z.array(alert), count: z.number().int().nonnegative() }),
  'OP-018': z.object({ items: z.array(trigger), count: z.number().int().nonnegative() }),
  'OP-025': z.object({ items: z.array(notifier), total: z.number().int().nonnegative(), count: z.number().int().nonnegative() }),
  'OP-026': providers, 'OP-029': notifier,
  'OP-031': directory, 'OP-032': directory,
  'OP-033': directory.omit({ page: true }).extend({ items: z.array(directoryTag) }),
  'OP-036': organization,
  'OP-041': z.record(z.string().regex(/^[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/), z.string().nullable()),
  'OP-042': z.record(z.string().regex(/^[0-9a-fA-F:.]+$/), z.array(z.string()).nullable()),
  'OP-043': headers, 'OP-044': address, 'OP-072': address,
  'OP-055': z.object({ items: z.array(z.string()), sourceFamily: z.literal('trends') }),
  'OP-056': z.object({ items: z.array(z.string()), sourceFamily: z.literal('trends') }),
  'OP-059': internetdb,
}
export const statsOutput = count.extend({ facets, buckets: z.array(facet.extend({ facet: z.string() })), count: z.number().int().nonnegative(), saved: artifact.optional() })
export const homeOutput = z.object({ bin: z.string(), description: z.string(), account: info, help: z.array(z.string()) })
export const doctorOutput = z.object({ status: z.literal('ok'), account: info })
const savedEvidence = z.object({ path: z.string(), bytes: z.number().int().nonnegative(), sha256: z.string() })
export const alertExportOutput = savedEvidence.extend({ count: z.number().int().nonnegative(), complete: z.literal(true) })
export const alertStatsOutput = z.object({ networks: z.array(z.string()), total: z.number().int().nonnegative(), items: z.array(z.object({ facet: z.string(), value: z.union([z.string(), z.number()]), count: z.number().int().nonnegative() })), count: z.number().int().nonnegative(), aggregation: z.enum(['exact', 'partial']), complete: z.boolean(), continuation: z.object({ network: z.string(), page: z.number().int().positive() }).optional(), saved: savedEvidence.optional() })
