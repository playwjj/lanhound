import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { setLocale, t } from './i18n'

describe('i18n', () => {
  it('substitutes parameters and falls back to English, then the key', () => {
    setLocale('zh')
    expect(t('unreviewed', { n: 3 })).toBe('还有 3 台设备未标记为已认识。')
    expect(t('no_such_key')).toBe('no_such_key')
    setLocale('en')
    expect(t('unreviewed', { n: 3 })).toBe('3 device(s) not yet marked as known.')
  })

  it('has the same keys in every language', () => {
    const src = readFileSync(new URL('./i18n.js', import.meta.url), 'utf8')
    const blocks = src.split(/\n {2}(?=\w+: \{)/).slice(1)
    const keys = blocks.map((b) => new Set([...b.matchAll(/\n {4}(\w+):/g)].map((m) => m[1])))
    const [en, zh] = keys
    expect([...en].filter((k) => !zh.has(k))).toEqual([])
    expect([...zh].filter((k) => !en.has(k))).toEqual([])
  })
})
