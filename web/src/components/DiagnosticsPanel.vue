<script setup>
import { onMounted, ref } from 'vue'
import { api } from '../api'
import { now } from '../state'
import { t } from '../i18n'
import { ago, dateTime } from '../format'

const data = ref(null)
const copied = ref(false)

async function load() {
  data.value = await api.diagnostics()
}
onMounted(load)

function attrs(e) {
  return Object.entries(e.attrs || {})
    .filter(([k]) => k !== 'component')
    .map(([k, v]) => `${k}=${v}`)
    .join(' ')
}

// Plain text for a bug report: version first, then the log lines.
function report() {
  const lines = [`LanHound ${data.value.version}`, `started ${data.value.startedAt}`, '']
  for (const e of data.value.logs) {
    lines.push(`${e.time} ${e.level} [${e.attrs?.component ?? '-'}] ${e.msg} ${attrs(e)}`.trim())
  }
  return lines.join('\n')
}

async function copy() {
  try {
    await navigator.clipboard.writeText(report())
    copied.value = true
    setTimeout(() => (copied.value = false), 2000)
  } catch {}
}
</script>

<template>
  <div v-if="data" class="diag">
    <p class="muted intro">{{ t('diagIntro') }}</p>
    <dl class="facts">
      <dt>{{ t('version') }}</dt>
      <dd class="mono">{{ data.version }}</dd>
      <dt>{{ t('diagStarted') }}</dt>
      <dd>{{ dateTime(data.startedAt) }} ({{ ago(data.startedAt, now) }})</dd>
    </dl>
    <div class="row">
      <strong>{{ t('diagLogs') }}</strong>
      <span class="grow"></span>
      <button type="button" class="btn small" @click="load">{{ t('refresh') }}</button>
      <button type="button" class="btn small" :disabled="!data.logs.length" @click="copy">{{ copied ? t('copied') : t('copyReport') }}</button>
    </div>
    <p v-if="!data.logs.length" class="ok small">{{ t('diagNone') }}</p>
    <ul v-else class="logs">
      <li v-for="(e, i) in data.logs" :key="i" :class="e.level.toLowerCase()">
        <span class="lvl">{{ e.level }}</span>
        <span class="muted small" :title="dateTime(e.time)">{{ ago(e.time, now) }}</span>
        <span class="comp mono small">{{ e.attrs?.component }}</span>
        <span class="msg">{{ e.msg }}</span>
        <span class="mono small muted attrs">{{ attrs(e) }}</span>
      </li>
    </ul>
    <p class="muted small">{{ t('diagLevelHint') }}</p>
  </div>
</template>

<style scoped>
.diag {
  display: grid;
  gap: 10px;
}
.intro {
  margin: 0;
  font-size: 13px;
}
.facts {
  display: grid;
  grid-template-columns: 110px 1fr;
  gap: 4px 12px;
  margin: 0;
}
.facts dt {
  color: var(--muted);
}
.facts dd {
  margin: 0;
}
.row {
  display: flex;
  gap: 8px;
  align-items: center;
}
.grow {
  flex: 1;
}
.logs {
  list-style: none;
  padding: 0;
  margin: 0;
  display: grid;
  gap: 6px;
  max-height: 360px;
  overflow-y: auto;
}
.logs li {
  display: flex;
  flex-wrap: wrap;
  gap: 4px 8px;
  align-items: baseline;
  border-left: 3px solid var(--amber);
  padding-left: 8px;
}
.logs li.error {
  border-left-color: var(--danger);
}
.lvl {
  font-size: 11px;
  font-weight: 700;
  color: var(--warn);
}
.error .lvl {
  color: var(--danger);
}
.msg {
  font-weight: 500;
}
.attrs {
  overflow-wrap: anywhere;
  width: 100%;
}
.small {
  font-size: 12px;
  margin: 0;
}
.ok {
  color: var(--ok);
}
</style>
