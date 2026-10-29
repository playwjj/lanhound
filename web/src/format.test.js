import { describe, expect, it } from 'vitest'
import { ago, displayName, ipKey, isZero } from './format'
import { setLocale } from './i18n'

describe('format', () => {
  it('treats Go zero times as empty', () => {
    expect(isZero('0001-01-01T00:00:00Z')).toBe(true)
    expect(isZero('')).toBe(true)
    expect(isZero('2026-10-29T10:00:00Z')).toBe(false)
  })

  it('orders IPv4 addresses numerically', () => {
    const ips = ['192.168.2.100', '192.168.2.9', '', '10.0.0.1']
    expect([...ips].sort((a, b) => ipKey(a).localeCompare(ipKey(b)))).toEqual(['10.0.0.1', '192.168.2.9', '192.168.2.100', ''])
  })

  it('prefers the user name, then the announced hostname, never the model', () => {
    expect(displayName({ name: 'NAS', hostname: 'DiskStation' })).toBe('NAS')
    expect(displayName({ name: '', hostname: 'DiskStation', model: 'DS920+' })).toBe('DiskStation')
    expect(displayName({ name: '', hostname: '', model: 'Linux/3.10 UPnP/1.0' })).toBe('')
  })

  it('writes relative times in the UI language', () => {
    const now = Date.parse('2026-10-29T12:00:00Z')
    setLocale('en')
    expect(ago('2026-10-29T11:59:50Z', now)).toBe('just now')
    expect(ago('2026-10-29T09:00:00Z', now)).toBe('3 hours ago')
    expect(ago('0001-01-01T00:00:00Z', now)).toBe('—')
    setLocale('zh')
    expect(ago('2026-10-29T09:00:00Z', now)).toBe('3小时前')
    setLocale('en')
  })
})
