export function clean(value: unknown, key: string): unknown {
  if (typeof value === 'string') {
    const form = new URLSearchParams({ key }).toString().slice(4)
    return value.split(key).join('[REDACTED]').split(encodeURIComponent(key)).join('[REDACTED]').split(form).join('[REDACTED]').split(JSON.stringify(key).slice(1, -1)).join('[REDACTED]')
  }
  if (Array.isArray(value)) return value.map(item => clean(item, key))
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([field, item]) => [field, /(?:key|secret|token|password|authorization)/i.test(field) ? '[REDACTED]' : clean(item, key)]))
  return value
}
