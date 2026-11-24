// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, expect, it } from 'vitest'
import {
  ADAPTIVE_DPR_P95_THRESHOLD_MS,
  ADAPTIVE_DPR_WINDOW,
  createAdaptiveDprController,
} from '../adaptiveDpr'

describe('adaptiveDpr — monotonic S11 pixel-ratio degradation', () => {
  it('holds at 2x when interactive p95 frame time stays within 24 ms', () => {
    const ctrl = createAdaptiveDprController(2)
    ctrl.beginInteraction()
    let t = 0
    for (let i = 0; i <= ADAPTIVE_DPR_WINDOW + 20; i++) {
      expect(ctrl.recordFrame(t)).toBeNull()
      t += 16 // 62.5 FPS
    }
    expect(ctrl.current()).toBe(2)
  })

  it('degrades monotonically 2 -> 1.5 -> 1 when 120 interactive frames exceed p95 > 24 ms and never steps back up', () => {
    const ctrl = createAdaptiveDprController(2)
    ctrl.beginInteraction()

    let t = 0
    let droppedTo: number | null = null
    for (let i = 0; i <= ADAPTIVE_DPR_WINDOW; i++) {
      const res = ctrl.recordFrame(t)
      if (res != null) droppedTo = res
      t += ADAPTIVE_DPR_P95_THRESHOLD_MS + 6 // 30 ms per frame
    }
    expect(droppedTo).toBe(1.5)
    expect(ctrl.current()).toBe(1.5)

    // Fast frames do NOT raise DPR back up in the same session.
    for (let i = 0; i <= ADAPTIVE_DPR_WINDOW; i++) {
      expect(ctrl.recordFrame(t)).toBeNull()
      t += 10
    }
    expect(ctrl.current()).toBe(1.5)

    // Another 120 slow frames steps down 1.5 -> 1.
    droppedTo = null
    for (let i = 0; i <= ADAPTIVE_DPR_WINDOW; i++) {
      const res = ctrl.recordFrame(t)
      if (res != null) droppedTo = res
      t += 32
    }
    expect(droppedTo).toBe(1)
    expect(ctrl.current()).toBe(1)

    // Already at 1x floor — further slow frames return null.
    for (let i = 0; i <= ADAPTIVE_DPR_WINDOW; i++) {
      expect(ctrl.recordFrame(t)).toBeNull()
      t += 40
    }
    expect(ctrl.current()).toBe(1)

    // Raising external cap after degradation still honors session floor.
    expect(ctrl.setCap(2)).toBe(1)
  })

  it('ignores frames outside active interaction and idle gaps between interactions', () => {
    const ctrl = createAdaptiveDprController(2, { windowSize: 16 })
    // Idle renders do not record.
    expect(ctrl.recordFrame(0)).toBeNull()
    expect(ctrl.recordFrame(200)).toBeNull()

    // Short fast bursts separated by long idle gaps must not trigger downgrade.
    let t = 0
    for (let burst = 0; burst < 10; burst++) {
      ctrl.beginInteraction()
      for (let i = 0; i < 6; i++) {
        expect(ctrl.recordFrame(t)).toBeNull()
        t += 14
      }
      ctrl.endInteraction()
      t += 5000
    }
    expect(ctrl.current()).toBe(2)
  })
})
