<script setup>
import { ref } from 'vue'
import { api } from '../api'
import { now, state } from '../state'
import { t } from '../i18n'
import { ago, isZero } from '../format'
import Icon from './Icon.vue'

const name = ref('')
const created = ref(null) // { probe, token } — the token is shown only now
const err = ref('')
const confirmId = ref(null)

const command = (token) =>
  `docker run -d --name lanhound-agent --restart unless-stopped --network host --cap-add=NET_RAW \\\n  passport888/lanhound agent --server ${location.origin} --token ${token}`

// The same command on one line, for pasting into any shell.
const oneLine = (token) => command(token).replace(/ \\\n {2}/, ' ')

async function add() {
  err.value = ''
  try {
    created.value = await api.addProbe(name.value)
    name.value = ''
  } catch (e) {
    err.value = e.message
  }
}

async function remove(id) {
  err.value = ''
  try {
    await api.removeProbe(id)
    confirmId.value = null
  } catch (e) {
    err.value = e.message
  }
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text)
  } catch {}
}
</script>

<template>
  <div class="probes">
    <h4>{{ t('probes') }}</h4>
    <p class="muted intro">{{ t('probesIntro') }}</p>

    <ul v-if="state.status?.probes?.length" class="list">
      <li v-for="p in state.status.probes" :key="p.id">
        <span class="dot" :class="{ on: p.online }"></span>
        <strong>{{ p.name }}</strong>
        <span class="muted small">
          <template v-if="isZero(p.lastSeen)">{{ t('probeNever') }}</template>
          <template v-else-if="p.online">{{ p.interfaces.map((i) => i.network).join(', ') || '—' }}</template>
          <template v-else>{{ t('probeOffline', { t: ago(p.lastSeen, now) }) }}</template>
        </span>
        <span class="grow"></span>
        <template v-if="confirmId === p.id">
          <button type="button" class="btn small" @click="confirmId = null">{{ t('cancel') }}</button>
          <button type="button" class="btn small danger solid" @click="remove(p.id)">{{ t('remove') }}</button>
        </template>
        <button v-else type="button" class="btn small danger" @click="confirmId = p.id"><Icon name="trash" :size="13" /></button>
      </li>
    </ul>

    <div v-if="created" class="created">
      <p class="small">{{ t('probeCreated', { name: created.probe.name }) }}</p>
      <pre class="mono">{{ command(created.token) }}</pre>
      <div class="row">
        <button type="button" class="btn small" @click="copy(oneLine(created.token))">{{ t('copy') }}</button>
        <button type="button" class="btn small" @click="created = null">{{ t('done') }}</button>
      </div>
    </div>

    <form class="row" @submit.prevent="add">
      <input v-model="name" type="text" maxlength="32" :placeholder="t('probeNamePh')" />
      <button type="submit" class="btn" :disabled="!name.trim()">+ {{ t('addProbe') }}</button>
    </form>
    <p v-if="err" class="err small">{{ err }}</p>
  </div>
</template>

<style scoped>
.probes {
  display: grid;
  gap: 10px;
}
h4 {
  margin: 6px 0 0;
}
.intro {
  margin: 0;
  font-size: 13px;
}
.list {
  list-style: none;
  padding: 0;
  margin: 0;
  display: grid;
  gap: 6px;
}
.list li {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.grow {
  flex: 1;
}
.created {
  border: 1px solid var(--accent);
  border-radius: var(--radius);
  padding: 10px 12px;
  background: var(--accent-soft);
}
.created p {
  margin: 0 0 6px;
}
pre {
  margin: 0 0 8px;
  white-space: pre-wrap;
  word-break: break-all;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 8px;
}
.row {
  display: flex;
  gap: 8px;
}
.row input {
  flex: 1;
}
.small {
  font-size: 12.5px;
}
.err {
  color: var(--danger);
}
</style>
