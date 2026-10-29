import { locale, t } from './i18n'

const ZERO = '0001-01-01T00:00:00Z'

export function isZero(ts) {
  return !ts || ts === ZERO || ts.startsWith('0001-')
}

export function ago(ts, now) {
  if (isZero(ts)) return '—'
  const s = Math.round((new Date(ts).getTime() - now) / 1000)
  if (Math.abs(s) < 45) return t('justNow')
  const rtf = new Intl.RelativeTimeFormat(locale.value === 'zh' ? 'zh-CN' : 'en', { numeric: 'auto' })
  const units = [
    ['day', 86400],
    ['hour', 3600],
    ['minute', 60],
  ]
  for (const [unit, sec] of units) {
    if (Math.abs(s) >= sec) return rtf.format(Math.round(s / sec), unit)
  }
  return rtf.format(s, 'second')
}

export function dateTime(ts) {
  if (isZero(ts)) return '—'
  return new Date(ts).toLocaleString(locale.value === 'zh' ? 'zh-CN' : undefined, {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  })
}

// The name to show for a device: one the user gave it, else the one it
// announced. The model hint (often a raw SSDP server string) is shown
// as a subtitle instead.
export function displayName(d) {
  return d.name || d.hostname || ''
}

// Sort key that orders IPv4 addresses numerically.
export function ipKey(ip) {
  if (!ip) return 'z'
  return ip
    .split('.')
    .map((p) => p.padStart(3, '0'))
    .join('.')
}
