<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { api } from '../api'
import { t, locale } from '../i18n'
import HeatGrid from './HeatGrid.vue'

// Devices online per hour, one row per day: "who was on the network at
// 2 a.m.?" at a glance.
const open = ref(readOpen())
const data = ref(null)
let timer

function readOpen() {
  try {
    return localStorage.getItem('lanhound.activity') !== 'closed'
  } catch {
    return true
  }
}
watch(open, (v) => {
  try {
    localStorage.setItem('lanhound.activity', v ? 'open' : 'closed')
  } catch {}
  if (v) load()
})

async function load() {
  try {
    data.value = await api.activity(7)
  } catch {}
}
onMounted(() => {
  if (open.value) load()
  timer = setInterval(() => open.value && load(), 5 * 60 * 1000)
})
onUnmounted(() => clearInterval(timer))

const grid = computed(() => {
  if (!data.value) return null
  const start = new Date(data.value.start).getTime()
  const loc = locale.value === 'zh' ? 'zh-CN' : undefined
  const dayFmt = new Intl.DateTimeFormat(loc, { weekday: 'short', month: 'numeric', day: 'numeric' })
  const rows = new Map()
  let max = 1
  let peak = 0
  data.value.hourly.forEach((n, i) => {
    const at = new Date(start + i * 3600e3)
    const key = at.toDateString()
    if (!rows.has(key)) rows.set(key, { label: dayFmt.format(at), cells: Array.from({ length: 24 }, () => ({ value: null, tip: '' })) })
    const h = at.getHours()
    rows.get(key).cells[h] = { value: n, tip: t('activityTip', { day: dayFmt.format(at), h: String(h).padStart(2, '0'), n }) }
    max = Math.max(max, n)
    peak = Math.max(peak, n)
  })
  return { rows: [...rows.values()].slice(-7), max, peak }
})
</script>

<template>
  <section class="card">
    <button class="head" :aria-expanded="open" @click="open = !open">
      <strong>{{ t('activity') }}</strong>
      <span class="muted small">{{ t('activitySub') }}</span>
      <span class="grow"></span>
      <span v-if="grid && open" class="muted small">{{ t('activityPeak', { n: grid.peak }) }}</span>
      <span class="chev" :class="{ open }">›</span>
    </button>
    <div v-if="open" class="body">
      <HeatGrid v-if="grid" :rows="grid.rows" :max="grid.max" :less="t('fewer')" :more="t('more')" />
      <p v-else class="muted small">…</p>
    </div>
  </section>
</template>

<style scoped>
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  margin-bottom: 14px;
}
.head {
  display: flex;
  align-items: baseline;
  gap: 10px;
  width: 100%;
  border: 0;
  background: none;
  padding: 10px 14px;
  text-align: left;
}
.grow {
  flex: 1;
}
.small {
  font-size: 12.5px;
}
.chev {
  display: inline-block;
  transition: transform 0.15s;
  color: var(--muted);
  font-size: 16px;
  line-height: 1;
}
.chev.open {
  transform: rotate(90deg);
}
.body {
  padding: 0 14px 12px;
}
@media (max-width: 520px) {
  .head .muted.small:not(:last-of-type) {
    display: none;
  }
}
</style>
