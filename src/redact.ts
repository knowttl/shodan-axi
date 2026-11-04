export function clean(value: unknown, key: string): unknown {
  if (typeof value === 'string') {
    const form = new URLSearchParams({ key }).toString().slice(4)
    return value.split(key).join('[REDACTED]').split(encodeURIComponent(key)).join('[REDACTED]').split(form).join('[REDACTED]').split(JSON.stringify(key).slice(1, -1)).join('[REDACTED]')
  }
  if (Array.isArray(value)) return value.map(item => clean(item, key))
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([field, item]) => [field, clean(item, key)]))
  return value
}

export function cleanUpstream(value: unknown): unknown {
  if (typeof value === 'string') return value
    .replace(/-----BEGIN ([A-Z0-9][A-Z0-9 -]*)-----[\s\S]*?-----END \1-----/g, '[REDACTED]')
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[REDACTED]')
    .replace(/\bAccountKey=[^;\s&]+/gi, 'AccountKey=[REDACTED]')
    .replace(/([?&](?:sig|signature)=)[^&#\s]+/gi, '$1[REDACTED]')
  if (Array.isArray(value)) return value.map(cleanUpstream)
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([field, item]) => [field, /(?:password|passwd|pass.?phrase|secret|token|api[_-]?key|authorization|credential|private[_-]?key|account[_-]?key|signature)|^key$/i.test(field) ? '[REDACTED]' : cleanUpstream(item)]))
  return value
}
