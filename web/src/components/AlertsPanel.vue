<script setup>
import { onMounted, onUnmounted, ref } from 'vue'
import { api } from '../api'
import { state, now, markAlertsSeen } from '../state'
import { t, locale } from '../i18n'
import { ago, dateTime } from '../format'
import Icon from './Icon.vue'

const emit = defineEmits(['close', 'select'])
const trustedIds = ref(new Set())
const error = ref('')

onMounted(() => {
  markAlertsSeen()
  window.addEventListener('keydown', onKey)
})
onUnmounted(() => {
  markAlertsSeen()
  window.removeEventListener('keydown', onKey)
})
function onKey(e) {
  if (e.key === 'Escape') emit('close')
}

const SEVERE = new Set(['arp_conflict', 'arp_flood', 'gateway_changed', 'rogue_dhcp', 'device_offline'])

function devName(d) {
  // A device LanHound knows may have been renamed since the alert.
  const live = d.id ? state.devices[d.id] : null
  return (live && (live.name || live.hostname)) || d.name || d.hostname || d.model || t('unnamed')
}

function minutes(sec) {
  const [mi, hr, dy] = locale.value === 'zh' ? ['分钟', '小时', '天'] : [' min', ' h', ' d']
  const m = Math.round(sec / 60)
  if (m < 60) return `${m}${mi}`
  const h = Math.floor(m / 60)
  return h < 48 ? `${h}${hr} ${m % 60}${mi}` : `${Math.floor(h / 24)}${dy}`
}

// title + optional explanation for one alert
function describe(a) {
  const m = a.data
  const d0 = m.devices?.[0] ?? {}
  switch (a.kind) {
    case 'new_device':
      return {
        title: m.devices.length === 1 ? `${t('al_new_device')}: ${devName(d0)}` : t('al_new_devices', { n: m.devices.length }),
      }
    case 'arp_conflict':
      return { title: t(m.gateway ? 'al_arp_conflict_gw' : 'al_arp_conflict', { ip: m.ip }), text: t('al_arp_conflict_tx') }
    case 'arp_flood':
      return { title: t('al_arp_flood', { name: devName(d0) }), text: t('al_arp_flood_tx', { count: m.count, s: m.seconds }) }
    case 'gateway_changed':
      return { title: t('al_gateway_changed', { ip: m.ip }), text: t('al_gateway_changed_tx'), labels: [t('was'), t('now')] }
    case 'rogue_dhcp':
      return { title: t('al_rogue_dhcp', { iface: m.interface }), text: t('al_rogue_dhcp_tx', { trusted: (m.trusted || []).join(', ') || '—' }) }
    case 'device_offline':
      return { title: t('al_device_offline', { name: devName(d0) }) }
    case 'device_online':
      return { title: t('al_device_online', { name: devName(d0) }), text: m.seconds ? t('al_away', { d: minutes(m.seconds) }) : '' }
  }
  return { title: a.kind }
}

async function trust(a) {
  error.value = ''
  try {
    await api.trustAlert(a.id)
    trustedIds.value = new Set([...trustedIds.value, a.id])
  } catch (e) {
    error.value = e.message
  }
}
</script>

<template>
  <div class="scrim" @click="emit('close')"></div>
  <aside class="panel" role="dialog" :aria-label="t('alerts')">
    <header>
      <Icon name="bell" />
      <strong>{{ t('alerts') }}</strong>
      <span class="grow"></span>
      <button class="btn icon" :title="t('close')" @click="emit('close')"><Icon name="x" /></button>
    </header>
    <div class="body">
      <p v-if="error" class="err">{{ error }}</p>
      <p v-if="!state.alerts.length" class="muted empty">{{ t('noAlerts') }}</p>
      <article v-for="a in state.alerts" :key="a.id" class="alert" :class="[a.kind, { severe: SEVERE.has(a.kind) }]">
        <div class="a-head">
          <span class="a-title">{{ describe(a).title }}</span>
          <span class="muted small" :title="dateTime(a.at)">{{ ago(a.at, now) }}</span>
        </div>
        <p v-if="describe(a).text" class="a-text">{{ describe(a).text }}</p>
        <ul class="devs">
          <li v-for="(d, i) in a.data.devices" :key="i">
            <span v-if="describe(a).labels" class="muted small">{{ describe(a).labels[i] }}:</span>
            <button v-if="d.id && state.devices[d.id]" class="link" @click="emit('select', d.id)">{{ devName(d) }}</button>
            <span v-else>{{ devName(d) }}</span>
            <span class="mono muted">{{ d.mac }}</span>
            <span v-if="d.ip" class="mono muted">{{ d.ip }}</span>
            <span v-if="d.vendor && !d.randomized" class="muted small">{{ d.vendor }}</span>
          </li>
        </ul>
        <div v-if="a.kind === 'rogue_dhcp'" class="a-act">
          <span v-if="trustedIds.has(a.id)" class="ok small">{{ t('trusted') }}</span>
          <button v-else class="btn small" @click="trust(a)"><Icon name="check" :size="14" />{{ t('trustServer') }}</button>
        </div>
      </article>
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
.panel {
  position: fixed;
  top: 0;
  right: 0;
  bottom: 0;
  width: min(480px, 100vw);
  background: var(--surface);
  border-left: 1px solid var(--border);
  z-index: 21;
  display: flex;
  flex-direction: column;
  box-shadow: -8px 0 30px rgb(15 23 42 / 0.15);
}
header {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 14px 16px;
  border-bottom: 1px solid var(--border);
}
.grow {
  flex: 1;
}
.body {
  overflow-y: auto;
  padding: 12px 16px 24px;
  display: grid;
  gap: 10px;
  align-content: start;
}
.empty {
  text-align: center;
  padding: 30px 10px;
}
.alert {
  border: 1px solid var(--border);
  border-left: 3px solid var(--accent);
  border-radius: 8px;
  padding: 10px 12px;
}
.alert.severe {
  border-left-color: var(--danger);
}
.alert.new_device {
  border-left-color: var(--amber);
}
.alert.device_online {
  border-left-color: var(--ok);
}
.a-head {
  display: flex;
  gap: 10px;
  align-items: baseline;
  justify-content: space-between;
}
.a-title {
  font-weight: 600;
}
.a-text {
  margin: 4px 0 0;
  font-size: 13px;
  color: var(--muted);
}
.devs {
  list-style: none;
  padding: 0;
  margin: 6px 0 0;
  display: grid;
  gap: 3px;
}
.devs li {
  display: flex;
  flex-wrap: wrap;
  gap: 4px 8px;
  align-items: baseline;
}
.link {
  border: 0;
  background: none;
  padding: 0;
  color: var(--accent);
  font-weight: 500;
}
.link:hover {
  text-decoration: underline;
}
.a-act {
  margin-top: 8px;
}
.small {
  font-size: 12px;
}
.ok {
  color: var(--ok);
}
.err {
  color: var(--danger);
}
</style>
