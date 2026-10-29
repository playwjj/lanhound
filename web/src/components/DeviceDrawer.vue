<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { api } from '../api'
import { now, state, upsert } from '../state'
import { t, locale } from '../i18n'
import { ago, dateTime, displayName } from '../format'
import Icon from './Icon.vue'
import InlineName from './InlineName.vue'
import HeatGrid from './HeatGrid.vue'

const props = defineProps({ device: Object })
const emit = defineEmits(['close', 'select'])

const history = ref({ sessions: [], events: [] })
const note = ref('')
const noteDirty = computed(() => note.value.trim() !== (props.device.note || ''))
const mergeTarget = ref('')
const showMerge = ref(false)
const confirmForget = ref(false)
const busy = ref(false)
const error = ref('')

async function load() {
  try {
    history.value = await api.history(props.device.id, 28)
  } catch (e) {
    error.value = e.message
  }
}

watch(
  () => props.device.id,
  () => {
    note.value = props.device.note || ''
    showMerge.value = confirmForget.value = false
    mergeTarget.value = ''
    error.value = ''
    load()
  },
  { immediate: true },
)
// Refresh the timeline when the device comes or goes.
watch(() => props.device.online, load)

function onKey(e) {
  if (e.key === 'Escape') emit('close')
}
onMounted(() => window.addEventListener('keydown', onKey))
onUnmounted(() => window.removeEventListener('keydown', onKey))

const similar = computed(() => (props.device.sameAs ? state.devices[props.device.sameAs] : null))
const why = computed(() => (props.device.sameAsWhy || []).map((w) => t('why_' + w)).join(locale.value === 'zh' ? '、' : ', '))
const others = computed(() =>
  Object.values(state.devices)
    .filter((d) => d.id !== props.device.id)
    .sort((a, b) => (displayName(a) || a.mac).localeCompare(displayName(b) || b.mac)),
)

async function run(fn) {
  busy.value = true
  error.value = ''
  try {
    await fn()
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}

const saveNote = () => run(async () => upsert(await api.patch(props.device.id, { note: note.value })))
const toggleCritical = () => run(async () => upsert(await api.patch(props.device.id, { critical: !props.device.critical })))
const toggleKnown = () => run(async () => upsert(await api.patch(props.device.id, { known: !props.device.known })))
const merge = (into) =>
  run(async () => {
    const merged = await api.merge(props.device.id, Number(into))
    upsert(merged)
    emit('select', merged.id)
  })
const forget = () =>
  run(async () => {
    await api.remove(props.device.id)
    emit('close')
  })

// Weekday × hour: share of each hour-slot the device was online over the
// last 28 days (only counting time since it was first seen).
const usual = computed(() => {
  const end = now.value
  const begin = Math.max(end - 28 * 864e5, new Date(props.device.firstSeen).getTime())
  const online = Array.from({ length: 7 }, () => new Array(24).fill(0))
  const total = Array.from({ length: 7 }, () => new Array(24).fill(0))
  const slot = (ms) => {
    const d = new Date(ms)
    return [(d.getDay() + 6) % 7, d.getHours()] // Monday first
  }
  // Exposure: how much of each slot lies inside the window.
  for (let t0 = Math.floor(begin / 3600e3) * 3600e3; t0 < end; t0 += 3600e3) {
    const span = Math.min(t0 + 3600e3, end) - Math.max(t0, begin)
    if (span > 0) {
      const [w, h] = slot(t0)
      total[w][h] += span
    }
  }
  for (const s of history.value.sessions) {
    let a = Math.max(new Date(s.start).getTime(), begin)
    const b = s.end.startsWith('0001') ? end : Math.min(new Date(s.end).getTime(), end)
    while (a < b) {
      const next = Math.min(Math.floor(a / 3600e3) * 3600e3 + 3600e3, b)
      const [w, h] = slot(a)
      online[w][h] += next - a
      a = next
    }
  }
  const loc = locale.value === 'zh' ? 'zh-CN' : undefined
  const fmt = new Intl.DateTimeFormat(loc, { weekday: 'short' })
  const monday = new Date(2024, 0, 1) // a Monday
  return online.map((hours, w) => {
    const day = fmt.format(new Date(monday.getTime() + w * 864e5))
    return {
      label: day,
      cells: hours.map((ms, h) => {
        if (!total[w][h]) return { value: null, tip: '' }
        const share = ms / total[w][h]
        return { value: share, tip: t('usualTip', { day, h: String(h).padStart(2, '0'), p: Math.round(share * 100) }) }
      }),
    }
  })
})

// Seven day rows, each with the online periods that fall into it.
const days = computed(() => {
  const out = []
  const today = new Date(now.value)
  today.setHours(0, 0, 0, 0)
  const fmt = new Intl.DateTimeFormat(locale.value === 'zh' ? 'zh-CN' : undefined, { weekday: 'short', month: 'numeric', day: 'numeric' })
  for (let i = 6; i >= 0; i--) {
    const start = new Date(today)
    start.setDate(today.getDate() - i)
    const end = new Date(start)
    end.setDate(start.getDate() + 1)
    const s0 = start.getTime()
    const s1 = end.getTime()
    const segs = []
    for (const s of history.value.sessions) {
      const a = new Date(s.start).getTime()
      const b = s.end.startsWith('0001') ? now.value : new Date(s.end).getTime()
      const from = Math.max(a, s0)
      const to = Math.min(b, s1, now.value)
      if (to > from) segs.push({ left: ((from - s0) / 864e5) * 100, width: Math.max(((to - from) / 864e5) * 100, 0.4) })
    }
    out.push({ label: fmt.format(start), segs })
  }
  return out
})
</script>

<template>
  <div class="scrim" @click="emit('close')"></div>
  <aside class="drawer" role="dialog" :aria-label="displayName(device) || device.mac">
    <header class="d-head">
      <span class="dot" :class="{ on: device.online }"></span>
      <div class="d-title">
        <InlineName :device="device" />
        <span class="muted small">{{ device.online ? t('online') : `${t('lastSeen')} ${ago(device.lastSeen, now)}` }}</span>
      </div>
      <button class="btn icon" :title="t('close')" @click="emit('close')"><Icon name="x" /></button>
    </header>

    <div class="d-body">
      <div v-if="similar" class="banner warn">
        <Icon name="merge" />
        <span class="grow">{{ t('sameName', { name: displayName(similar) || similar.mac, why }) }}</span>
        <button class="btn small" :disabled="busy" @click="merge(similar.id)">{{ t('mergeInto') }}</button>
      </div>
      <p v-if="error" class="error">{{ error }}</p>

      <div class="known-row">
        <button class="btn" :class="{ primary: !device.known }" :disabled="busy" @click="toggleKnown">
          <Icon name="check" :size="14" />{{ device.known ? t('unmarkKnown') : t('markKnown') }}
        </button>
        <span v-if="!device.known" class="badge new">{{ t('new') }}</span>
        <span v-else class="muted small">{{ t('known') }} ✓</span>
      </div>

      <label class="crit">
        <input type="checkbox" :checked="device.critical" :disabled="busy" @change="toggleCritical" />
        <span>
          <strong>{{ t('critical') }}</strong>
          <span class="muted small"> — {{ t('criticalHelp') }}</span>
        </span>
      </label>

      <dl class="facts">
        <dt>{{ t('ip') }}</dt>
        <dd class="mono">{{ device.ip || '—' }}</dd>
        <template v-if="device.ipv6?.length">
          <dt>IPv6</dt>
          <dd>
            <div v-for="a in device.ipv6" :key="a" class="mono">{{ a }}</div>
          </dd>
        </template>
        <dt>{{ t('hostname') }}</dt>
        <dd>
          {{ device.hostname || '—' }}
          <span v-if="device.hostname" class="muted small">{{ t('via', { src: device.hostnameSource }) }}</span>
        </dd>
        <template v-if="device.model">
          <dt>{{ t('model') }}</dt>
          <dd>{{ device.model }}</dd>
        </template>
        <dt>{{ t('vendor') }}</dt>
        <dd>{{ device.vendor || '—' }}</dd>
        <template v-if="device.dhcpFingerprint">
          <dt>{{ t('dhcpFingerprint') }}</dt>
          <dd class="mono small">{{ device.dhcpFingerprint }}</dd>
        </template>
        <dt>{{ t('interface') }}</dt>
        <dd>{{ device.interface || '—' }}</dd>
        <dt>{{ t('macs') }}</dt>
        <dd>
          <div v-for="m in device.macs" :key="m" class="mono">
            {{ m }} <span v-if="m === device.mac && device.macs.length > 1" class="muted small">●</span>
          </div>
          <span v-if="device.randomized" class="badge random" :title="t('randomMacTip')">{{ t('randomMac') }}</span>
        </dd>
        <dt>{{ t('firstSeen') }}</dt>
        <dd>{{ dateTime(device.firstSeen) }}</dd>
        <dt>{{ t('lastSeen') }}</dt>
        <dd>{{ dateTime(device.lastSeen) }}</dd>
      </dl>

      <label class="field">
        <span class="label">{{ t('note') }}</span>
        <textarea v-model="note" rows="2" maxlength="500" :placeholder="t('notePlaceholder')"></textarea>
      </label>
      <div v-if="noteDirty" class="right">
        <button class="btn small" @click="note = device.note || ''">{{ t('cancel') }}</button>
        <button class="btn small primary" :disabled="busy" @click="saveNote">{{ t('save') }}</button>
      </div>

      <h3>{{ t('history') }}</h3>
      <div class="timeline">
        <div v-for="d in days" :key="d.label" class="day">
          <span class="day-label muted">{{ d.label }}</span>
          <span class="bar">
            <span v-for="(s, i) in d.segs" :key="i" class="seg" :style="{ left: s.left + '%', width: s.width + '%' }"></span>
          </span>
        </div>
        <div class="day axis muted">
          <span></span>
          <span class="ticks"><span>0</span><span>6</span><span>12</span><span>18</span><span>24</span></span>
        </div>
      </div>

      <h3>{{ t('usualHours') }}</h3>
      <HeatGrid :rows="usual" :max="1" :less="t('lessOnline')" :more="t('moreOnline')" />

      <h3>{{ t('events') }}</h3>
      <ul class="events">
        <li v-for="(e, i) in history.events" :key="i">
          <span class="ev-kind" :class="e.kind">{{ t('ev_' + e.kind) }}</span>
          <span class="ev-detail">{{ e.detail }}</span>
          <span class="muted small ev-time">{{ dateTime(e.at) }}</span>
        </li>
        <li v-if="!history.events.length" class="muted">{{ t('noEvents') }}</li>
      </ul>

      <div class="danger-zone">
        <template v-if="!showMerge">
          <button class="btn small" @click="showMerge = true"><Icon name="merge" :size="14" />{{ t('mergeManual') }}</button>
        </template>
        <div v-else class="merge-box">
          <p class="muted small">{{ t('mergeHelp') }}</p>
          <div class="merge-row">
            <select v-model="mergeTarget">
              <option value="" disabled>{{ t('pick') }}</option>
              <option v-for="o in others" :key="o.id" :value="o.id">{{ displayName(o) || o.mac }} — {{ o.ip || o.mac }}</option>
            </select>
            <button class="btn small primary" :disabled="!mergeTarget || busy" @click="merge(mergeTarget)">{{ t('merge') }}</button>
            <button class="btn small" @click="showMerge = false">{{ t('cancel') }}</button>
          </div>
        </div>

        <template v-if="!confirmForget">
          <button class="btn small danger" @click="confirmForget = true"><Icon name="trash" :size="14" />{{ t('forget') }}</button>
        </template>
        <div v-else class="confirm">
          <p class="small">{{ t('forgetConfirm') }}</p>
          <div class="right">
            <button class="btn small" @click="confirmForget = false">{{ t('cancel') }}</button>
            <button class="btn small danger solid" :disabled="busy" @click="forget">{{ t('yesForget') }}</button>
          </div>
        </div>
      </div>
    </div>
  </aside>
</template>

<style scoped>
.scrim {
  position: fixed;
  inset: 0;
  background: rgb(15 23 42 / 0.35);
  z-index: 20;
}
.drawer {
  position: fixed;
  top: 0;
  right: 0;
  bottom: 0;
  width: min(460px, 100vw);
  background: var(--surface);
  border-left: 1px solid var(--border);
  z-index: 21;
  display: flex;
  flex-direction: column;
  box-shadow: -8px 0 30px rgb(15 23 42 / 0.15);
}
.d-head {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 14px 16px;
  border-bottom: 1px solid var(--border);
}
.d-title {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
}
.d-title :deep(.name-btn) {
  font-size: 16px;
}
.d-body {
  overflow-y: auto;
  padding: 16px;
}
.small {
  font-size: 12px;
}
.grow {
  flex: 1;
}
.error {
  color: var(--danger);
}
.known-row {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 14px;
}
.crit {
  display: flex;
  gap: 8px;
  align-items: baseline;
  margin-bottom: 14px;
  cursor: pointer;
}
.facts {
  display: grid;
  grid-template-columns: 110px 1fr;
  gap: 7px 12px;
  margin: 0 0 16px;
}
.facts dt {
  color: var(--muted);
}
.facts dd {
  margin: 0;
  min-width: 0;
  overflow-wrap: anywhere;
}
.field {
  display: block;
}
.label {
  display: block;
  color: var(--muted);
  margin-bottom: 4px;
}
textarea {
  resize: vertical;
}
.right {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  margin-top: 8px;
}
h3 {
  font-size: 13px;
  text-transform: uppercase;
  letter-spacing: 0.4px;
  color: var(--muted);
  margin: 20px 0 8px;
}
.timeline {
  display: grid;
  gap: 5px;
}
.day {
  display: grid;
  grid-template-columns: 92px 1fr;
  align-items: center;
  gap: 8px;
}
.day-label {
  font-size: 12px;
  white-space: nowrap;
}
.bar {
  position: relative;
  height: 12px;
  border-radius: 3px;
  background: var(--surface-2);
  border: 1px solid var(--border);
  overflow: hidden;
}
.seg {
  position: absolute;
  top: 0;
  bottom: 0;
  background: var(--ok);
  opacity: 0.85;
}
.axis {
  font-size: 10.5px;
}
.ticks {
  display: flex;
  justify-content: space-between;
}
.events {
  list-style: none;
  padding: 0;
  margin: 0;
  display: grid;
  gap: 6px;
}
.events li {
  display: grid;
  grid-template-columns: auto 1fr auto;
  gap: 8px;
  align-items: baseline;
}
.ev-kind {
  font-size: 12px;
  font-weight: 600;
}
.ev-kind.new {
  color: var(--warn);
}
.ev-kind.online {
  color: var(--ok);
}
.ev-kind.offline {
  color: var(--muted);
}
.ev-detail {
  font-family: var(--mono);
  font-size: 12px;
  overflow-wrap: anywhere;
}
.ev-time {
  white-space: nowrap;
}
.danger-zone {
  margin-top: 24px;
  padding-top: 14px;
  border-top: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 10px;
}
.merge-box,
.confirm {
  width: 100%;
}
.merge-row {
  display: flex;
  gap: 8px;
}
.merge-row select {
  flex: 1;
  min-width: 0;
}
.confirm p,
.merge-box p {
  margin: 0 0 6px;
}
</style>
