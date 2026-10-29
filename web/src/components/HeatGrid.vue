<script setup>
import { computed, ref } from 'vue'

// A rows × 24-hour heat map. One hue, light → dark for more (dark mode
// flips the anchor: dark → light). Zero is a neutral empty cell, so
// "nothing" never reads as "a little".
const props = defineProps({
  rows: Array, // [{ label, cells: [{ value, tip }] }]
  max: Number, // value that maps to the darkest step (≥ 1)
  less: String,
  more: String,
})

const STEPS = 5
function step(v) {
  if (!v) return 0
  return Math.min(STEPS, Math.max(1, Math.ceil((v / Math.max(props.max, 1)) * STEPS)))
}

const tip = ref(null) // { text, x, y }
const wrap = ref(null)
function show(e, cell) {
  if (cell.value == null) return
  const box = wrap.value.getBoundingClientRect()
  const r = e.currentTarget.getBoundingClientRect()
  tip.value = { text: cell.tip, x: r.left - box.left + r.width / 2, y: r.top - box.top }
}
const ticks = [0, 6, 12, 18, 24]
const legend = computed(() => Array.from({ length: STEPS }, (_, i) => i + 1))
</script>

<template>
  <div ref="wrap" class="heat" @pointerleave="tip = null">
    <div v-for="row in rows" :key="row.label" class="row">
      <span class="label">{{ row.label }}</span>
      <span class="cells">
        <span
          v-for="(c, h) in row.cells"
          :key="h"
          class="cell"
          :class="['s' + step(c.value), { future: c.value == null }]"
          :tabindex="c.value == null ? -1 : 0"
          :aria-label="c.tip"
          @pointerenter="show($event, c)"
          @focus="show($event, c)"
          @blur="tip = null"
        ></span>
      </span>
    </div>
    <div class="row axis">
      <span></span>
      <span class="ticks"><span v-for="t in ticks" :key="t">{{ t }}</span></span>
    </div>
    <div class="legend">
      <span>{{ less }}</span>
      <span v-for="s in legend" :key="s" class="cell" :class="'s' + s"></span>
      <span>{{ more }}</span>
    </div>
    <div v-if="tip" class="tip" :style="{ left: tip.x + 'px', top: tip.y + 'px' }">{{ tip.text }}</div>
  </div>
</template>

<style scoped>
.heat {
  --h0: var(--surface-2);
  --h1: #dbe8f6;
  --h2: #a9c8ea;
  --h3: #6c9fd6;
  --h4: #2f6fb5;
  --h5: #12355b;
  position: relative;
  display: grid;
  gap: 2px;
}
@media (prefers-color-scheme: dark) {
  .heat {
    --h1: #1b3354;
    --h2: #24507f;
    --h3: #3473b0;
    --h4: #5e9ad6;
    --h5: #a8cdf2;
  }
}
.row {
  display: grid;
  grid-template-columns: 74px 1fr;
  gap: 8px;
  align-items: center;
}
.label {
  font-size: 11.5px;
  color: var(--muted);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.cells {
  display: grid;
  grid-template-columns: repeat(24, 1fr);
  gap: 2px;
}
.cell {
  height: 14px;
  border-radius: 2px;
  background: var(--h0);
  outline-offset: 1px;
}
.cell.s0 {
  box-shadow: inset 0 0 0 1px var(--border);
}
.cell.s1 {
  background: var(--h1);
}
.cell.s2 {
  background: var(--h2);
}
.cell.s3 {
  background: var(--h3);
}
.cell.s4 {
  background: var(--h4);
}
.cell.s5 {
  background: var(--h5);
}
.cell.future {
  background: none;
  box-shadow: none;
}
.cells .cell:not(.future):hover,
.cells .cell:focus-visible {
  outline: 2px solid var(--text);
}
.axis {
  font-size: 10.5px;
  color: var(--muted);
}
.ticks {
  display: flex;
  justify-content: space-between;
}
.legend {
  display: flex;
  align-items: center;
  gap: 3px;
  justify-content: flex-end;
  font-size: 11px;
  color: var(--muted);
  margin-top: 4px;
}
.legend .cell {
  width: 14px;
  height: 10px;
}
.legend span:first-child {
  margin-right: 3px;
}
.legend span:last-child {
  margin-left: 3px;
}
.tip {
  position: absolute;
  transform: translate(-50%, calc(-100% - 6px));
  background: var(--text);
  color: var(--surface);
  font-size: 12px;
  padding: 4px 8px;
  border-radius: 6px;
  white-space: nowrap;
  pointer-events: none;
  z-index: 5;
}
@media (max-width: 520px) {
  .row {
    grid-template-columns: 52px 1fr;
  }
  .cell {
    height: 11px;
  }
}
</style>
