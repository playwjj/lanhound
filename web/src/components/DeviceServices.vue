<script setup>
import { ref } from 'vue'
import { api } from '../api'
import { now } from '../state'
import { t } from '../i18n'
import { ago, isZero } from '../format'

// The device panel's open services, with a manual "probe now".
const props = defineProps({ device: { type: Object, required: true } })
const probing = ref(false)
const error = ref('')

async function probeNow() {
  probing.value = true
  error.value = ''
  try {
    await api.probe(props.device.id)
  } catch (e) {
    error.value = e.message
  }
  // The result arrives over the live stream; stop the spinner after a bit.
  setTimeout(() => (probing.value = false), 6000)
}
</script>

<template>
  <h3 class="section-title svc-head">
    {{ t('services') }}
    <span v-if="!isZero(device.servicesAt)" class="muted small">{{ t('svcAt', { t: ago(device.servicesAt, now) }) }}</span>
    <button class="btn small" :disabled="probing" @click="probeNow">{{ probing ? t('svcProbing') : t('svcProbe') }}</button>
  </h3>
  <p v-if="error" class="error small">{{ error }}</p>
  <ul v-if="device.services?.length" class="svcs">
    <li v-for="s in device.services" :key="s.port">
      <span class="mono port">{{ s.port }}</span>
      <a v-if="s.url" :href="s.url" target="_blank" rel="noopener noreferrer">{{ s.name }}</a>
      <span v-else>{{ s.name }}</span>
      <span v-if="s.risky" class="badge risky" :title="t('svcRiskyTip')">{{ t('svcRisky') }}</span>
      <span class="muted small detail">{{ s.detail }}</span>
    </li>
  </ul>
  <p v-else class="muted small">{{ isZero(device.servicesAt) ? t('svcNever') : t('svcNone') }}</p>
</template>

<style scoped>
.small {
  font-size: 12px;
}
.error {
  color: var(--danger);
}
.svc-head {
  display: flex;
  align-items: center;
  gap: 10px;
}
.svc-head .btn {
  margin-left: auto;
  text-transform: none;
  letter-spacing: 0;
}
.svcs {
  list-style: none;
  padding: 0;
  margin: 0 0 16px;
  display: grid;
  gap: 4px;
}
.svcs li {
  display: flex;
  gap: 8px;
  align-items: baseline;
  flex-wrap: wrap;
}
.svcs .port {
  min-width: 44px;
}
.svcs a {
  color: var(--accent);
}
.svcs .detail {
  overflow-wrap: anywhere;
}
.badge.risky {
  background: var(--danger-soft);
  color: var(--danger);
}
</style>
