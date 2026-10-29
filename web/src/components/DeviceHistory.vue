<script setup>
import { computed, ref, watch } from 'vue'
import { api } from '../api'
import { now } from '../state'
import { t, locale } from '../i18n'
import { dateTime } from '../format'
import { dayStrips, usualHours } from '../presence'
import HeatGrid from './HeatGrid.vue'

// The device panel's history: 7-day timeline, usual hours, events.
const props = defineProps({ device: { type: Object, required: true } })

const history = ref({ sessions: [], events: [] })
const error = ref('')

async function load() {
  error.value = ''
  try {
    history.value = await api.history(props.device.id, 28)
  } catch (e) {
    error.value = e.message
  }
}
watch(() => props.device.id, load, { immediate: true })
watch(() => props.device.online, load) // a session opened or closed

const loc = computed(() => (locale.value === 'zh' ? 'zh-CN' : undefined))
const days = computed(() => dayStrips(history.value.sessions, now.value, loc.value))
const usual = computed(() =>
  usualHours(history.value.sessions, new Date(props.device.firstSeen).getTime(), now.value, loc.value, (day, h, p) =>
    t('usualTip', { day, h: String(h).padStart(2, '0'), p }),
  ),
)
</script>

<template>
  <p v-if="error" class="error">{{ error }}</p>

  <h3 class="section-title">{{ t('history') }}</h3>
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

  <h3 class="section-title">{{ t('usualHours') }}</h3>
  <HeatGrid :rows="usual" :max="1" :less="t('lessOnline')" :more="t('moreOnline')" />

  <h3 class="section-title">{{ t('events') }}</h3>
  <ul class="events">
    <li v-for="(e, i) in history.events" :key="i">
      <span class="ev-kind" :class="e.kind">{{ t('ev_' + e.kind) }}</span>
      <span class="ev-detail">{{ e.detail }}</span>
      <span class="muted small ev-time">{{ dateTime(e.at) }}</span>
    </li>
    <li v-if="!history.events.length" class="muted">{{ t('noEvents') }}</li>
  </ul>
</template>

<style scoped>
.error {
  color: var(--danger);
}
.small {
  font-size: 12px;
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
</style>
