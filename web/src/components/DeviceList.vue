<script setup>
import { api } from '../api'
import { now, state, upsert } from '../state'
import { t, locale } from '../i18n'
import { ago, dateTime, displayName } from '../format'
import Icon from './Icon.vue'
import InlineName from './InlineName.vue'

defineProps({ devices: Array })
const emit = defineEmits(['select'])

async function toggleKnown(d) {
  upsert(await api.patch(d.id, { known: !d.known }))
}

function whyText(d) {
  return (d.sameAsWhy || []).map((w) => t('why_' + w)).join(locale.value === 'zh' ? '、' : ', ')
}

function subtitle(d) {
  const parts = []
  if (d.kind) parts.push(t('kind_' + d.kind))
  if (d.name && d.hostname && d.name !== d.hostname) parts.push(d.hostname)
  if (d.model && d.model !== displayName(d)) parts.push(d.model)
  if (d.note) parts.push(d.note)
  return parts.join(' · ')
}
</script>

<template>
  <div class="list" v-if="devices.length">
    <div class="row head">
      <span></span>
      <span>{{ t('name') }}</span>
      <span>{{ t('ip') }}</span>
      <span>{{ t('mac') }}</span>
      <span>{{ t('vendor') }}</span>
      <span>{{ t('lastSeen') }}</span>
      <span></span>
    </div>
    <div
      v-for="d in devices"
      :key="d.id"
      class="row"
      :class="{ off: !d.online, fresh: !d.known }"
      tabindex="0"
      @click="emit('select', d.id)"
      @keydown.enter="emit('select', d.id)"
    >
      <span class="c-status"><span class="dot" :class="{ on: d.online }" :title="d.online ? t('online') : t('offline')"></span></span>
      <span class="c-name">
        <span class="name-line">
          <InlineName :device="d" />
          <span v-if="!d.known" class="badge new">{{ t('new') }}</span>
          <span v-if="d.critical" class="badge crit" :title="t('criticalHelp')">{{ t('criticalBadge') }}</span>
          <span
            v-if="d.link"
            class="badge link"
            :class="[d.link.type, { guess: !d.link.certain }]"
            :title="d.link.certain ? [d.link.band, d.link.signal ? d.link.signal + ' dBm' : '', t('linkVia', { r: d.link.via })].filter(Boolean).join(' · ') : t('linkGuessTip')"
          >{{ t('link_' + d.link.type) }}{{ d.link.certain ? '' : '?' }}</span>
          <span v-if="d.sameAs && state.devices[d.sameAs]" class="badge random same" :title="t('sameName', { name: state.devices[d.sameAs].name || state.devices[d.sameAs].hostname || state.devices[d.sameAs].mac, why: whyText(d) })">
            <Icon name="merge" :size="11" />{{ t('sameNameBadge') }}
          </span>
        </span>
        <span class="sub muted" v-if="subtitle(d)">{{ subtitle(d) }}</span>
      </span>
      <span class="c-ip mono">{{ d.ip || '—' }}</span>
      <span class="c-mac">
        <span class="mono">{{ d.mac }}</span>
        <span v-if="d.randomized" class="badge random" :title="t('randomMacTip')">{{ t('randomMac') }}</span>
      </span>
      <span class="c-vendor muted" :title="d.vendor">{{ d.randomized ? '—' : d.vendor || '—' }}</span>
      <span class="c-seen muted" :title="`${t('firstSeen')}: ${dateTime(d.firstSeen)}`">
        {{ d.online ? t('online') : ago(d.lastSeen, now) }}
      </span>
      <span class="c-act" @click.stop>
        <button
          class="known"
          :class="{ on: d.known }"
          :title="d.known ? t('unmarkKnown') : t('markKnown')"
          :aria-pressed="d.known"
          @click="toggleKnown(d)"
        >
          <Icon name="check" :size="14" />
        </button>
      </span>
    </div>
  </div>
</template>

<style scoped>
.list {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  overflow: hidden;
}
.row {
  display: grid;
  grid-template-columns: 22px minmax(180px, 2.2fr) 120px 1.7fr 1.5fr 110px 40px;
  gap: 12px;
  align-items: center;
  padding: 9px 14px;
  border-top: 1px solid var(--border);
  cursor: pointer;
  min-width: 0;
}
.row > span {
  min-width: 0;
}
.row:first-child {
  border-top: 0;
}
.row:not(.head):hover {
  background: var(--surface-2);
}
.row:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: -2px;
}
.row.head {
  cursor: default;
  font-size: 12px;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.4px;
  padding-top: 7px;
  padding-bottom: 7px;
  background: var(--surface-2);
}
.row.off .c-name,
.row.off .c-ip,
.row.off .c-mac {
  opacity: 0.62;
}
.row.fresh {
  box-shadow: inset 3px 0 0 var(--amber);
}
.c-name {
  display: flex;
  flex-direction: column;
}
.name-line {
  display: flex;
  align-items: center;
  gap: 6px;
  min-width: 0;
}
.badge.link {
  background: var(--surface-2);
  color: var(--muted);
  border: 1px solid var(--border);
}
.badge.link.guess {
  border-style: dashed;
  background: none;
}
.crit {
  background: var(--danger-soft);
  color: var(--danger);
}
.same {
  gap: 3px;
}
.sub {
  font-size: 12.5px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.c-mac {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}
.c-vendor,
.c-seen {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 13px;
}
.known {
  width: 28px;
  height: 28px;
  border-radius: 50%;
  border: 1px dashed var(--border);
  background: none;
  color: var(--muted);
  display: inline-flex;
  align-items: center;
  justify-content: center;
}
.known:hover {
  border-color: var(--ok);
  color: var(--ok);
}
.known.on {
  border: 0;
  background: var(--ok-soft);
  color: var(--ok);
}

@media (max-width: 900px) {
  .row {
    grid-template-columns: 22px minmax(150px, 2fr) 110px 1.6fr 90px 40px;
  }
  .c-vendor,
  .row.head span:nth-child(5) {
    display: none;
  }
}

/* Phones: each device becomes a card. */
@media (max-width: 640px) {
  .row.head {
    display: none;
  }
  .row {
    grid-template-columns: 18px 1fr auto;
    grid-template-areas:
      'status name act'
      '. ip act'
      '. mac mac'
      '. seen seen';
    row-gap: 3px;
    padding: 11px 12px;
  }
  .c-status {
    grid-area: status;
  }
  .c-name {
    grid-area: name;
  }
  .c-ip {
    grid-area: ip;
  }
  .c-mac {
    grid-area: mac;
  }
  .c-seen {
    grid-area: seen;
    font-size: 12px;
  }
  .c-act {
    grid-area: act;
    align-self: center;
  }
}
</style>
