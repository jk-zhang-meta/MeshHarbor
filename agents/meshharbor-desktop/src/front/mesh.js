// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
/*
 * FR-84 D5c — the mesh graph (`window.Roomler.Mesh`), a vanilla-SVG port of
 * the web dashboard's ui/src/components/stats/MeshGraph.vue.
 *
 * Same picture, same rules: the control plane at the centre, one node per
 * device on a ring (online first, then by name, so a device does not jump
 * around between refreshes), a spoke per control-plane link, and one chord
 * per peer carrier coloured by carrier class. An ASYMMETRIC pair — direct one
 * way, relayed the other — is drawn in both colours, each half wearing its own
 * end's carrier, because that is real routing information (one side behind a
 * corporate firewall), not an inconsistency to average away.
 *
 * Differences from the web, on purpose:
 *   - no d3: a chord is a hand-rolled quadratic Bézier `M a Q m b`, its
 *     control point at the pair's mid-angle and 0.35·r from the centre — the
 *     same bowed-to-the-middle shape as d3's bundled radial line. The mid-angle
 *     is taken along the SHORTER arc, so two neighbours either side of 12
 *     o'clock get a short chord, not a loop through the far side.
 *   - this device is emphasised (a second ring, a bold label), from the
 *     payload's `self_node_id`.
 *   - labels come from the server (`label`: display name first), because the
 *     companion has no agent list to join against.
 *
 * The edge-reading rules (qualifiedCarrier / edgeSides /
 * participatingCarriers) are NOT reimplemented here: they come from
 * `window.RoomlerMesh`, generated from ui/src/utils/mesh.ts (mesh-util.js),
 * so the web and desktop graphs read an edge identically.
 *
 * Colours are CSS custom properties (--mesh-direct/relay/derp/tunnel/blocked,
 * styles.css) applied through classes; every label is textContent.
 */
(function () {
  'use strict';

  const SVG_NS = 'http://www.w3.org/2000/svg';
  const TAU = Math.PI * 2;

  /** The carrier classes, in the web's order and wording. */
  const CARRIERS = [
    { key: 'direct', label: 'Direct' },
    { key: 'relay', label: 'TURN relay' },
    { key: 'derp', label: 'DERP' },
    { key: 'tunnel', label: 'Tunnel' },
    { key: 'blocked', label: 'Blocked' },
  ];
  const KNOWN = new Set(CARRIERS.map((c) => c.key));

  let instances = 0;

  function util() {
    // Generated from ui/src/utils/mesh.ts — see mesh-util.js.
    return window.RoomlerMesh;
  }

  function svgEl(tag, attrs, parent) {
    const el = document.createElementNS(SVG_NS, tag);
    if (attrs) {
      for (const k of Object.keys(attrs)) {
        if (attrs[k] !== undefined && attrs[k] !== null) el.setAttribute(k, String(attrs[k]));
      }
    }
    if (parent) parent.appendChild(el);
    return el;
  }

  function round(n) {
    return Math.round(n * 10) / 10;
  }

  function carrierClass(c) {
    return KNOWN.has(c) ? c : 'other';
  }

  /** Signed angular distance a → b, folded into (−π, π]. */
  function angleDelta(a, b) {
    let d = (b - a) % TAU;
    if (d > Math.PI) d -= TAU;
    if (d <= -Math.PI) d += TAU;
    return d;
  }

  /** Place `nodes` on a ring of `radius` — online first, then by name,
   *  starting at 12 o'clock (angle = i/n·2π − π/2). */
  function layout(nodes, radius) {
    const ordered = nodes
      .slice()
      .sort((a, b) => Number(b.online) - Number(a.online) || a.name.localeCompare(b.name));
    const n = ordered.length || 1;
    return ordered.map((node, i) => {
      const angle = (i / n) * TAU - Math.PI / 2;
      return Object.assign({}, node, {
        angle,
        x: Math.cos(angle) * radius,
        y: Math.sin(angle) * radius,
      });
    });
  }

  /** The chord between two placed nodes (see the file comment). */
  function chordPath(a, b, radius) {
    const mid = a.angle + angleDelta(a.angle, b.angle) / 2;
    const mx = Math.cos(mid) * radius * 0.35;
    const my = Math.sin(mid) * radius * 0.35;
    return (
      'M ' + round(a.x) + ' ' + round(a.y) +
      ' Q ' + round(mx) + ' ' + round(my) +
      ' ' + round(b.x) + ' ' + round(b.y)
    );
  }

  /** The payload's nodes, joined to the agents behind them — the same join
   *  the web dashboard does, with the server's `label` preferred. */
  function nodesFromView(view) {
    const agents = new Map(((view && view.agents) || []).map((a) => [a.id, a]));
    return ((view && view.nodes) || []).map((n) => {
      const agent = n.agent_id_hex ? agents.get(n.agent_id_hex) : null;
      const name =
        n.label ||
        (agent && (agent.display_name || agent.name)) ||
        n.name ||
        n.overlay_ip ||
        String(n.id || '').slice(-6);
      return {
        id: n.id,
        name,
        // An agent's presence is the truth for the dot; a tunnel-client node
        // has no agent, so its own row's status stands in.
        online: agent ? agent.last_presence === 'online' : n.status === 'online',
        relay_home: (agent && agent.relay_home) || n.relay_home || null,
        version: (agent && agent.agent_version) || null,
        isSelf: !!view.self_node_id && n.id === view.self_node_id,
      };
    });
  }

  /** One tooltip line per reported direction, in the CLI's vocabulary. */
  function directionLine(fromName, toName, end) {
    return (
      fromName + ' → ' + toName + ': ' + util().qualifiedCarrier(end.carrier, end.relay) +
      (end.rtt_ms != null ? ' · ' + end.rtt_ms + ' ms' : '') +
      (end.stalled ? ' · stalled' : '')
    );
  }

  function edgeLines(e, a, b, sides) {
    const lines = [];
    if (sides.from) lines.push(directionLine(a.name, b.name, sides.from));
    if (sides.to) lines.push(directionLine(b.name, a.name, sides.to));
    if (!lines.length) {
      lines.push(
        a.name + ' ↔ ' + b.name + ' · ' + e.carrier + (e.rtt_ms != null ? ' · ' + e.rtt_ms + ' ms' : ''),
      );
    }
    const endStalled = (sides.from && sides.from.stalled) || (sides.to && sides.to.stalled);
    if (e.stalled && !endStalled) lines.push('stalled');
    if (e.reports === 1) lines.push('one-sided — only one end reported');
    return lines;
  }

  /**
   * opts: { wrap, svg, tip, legend, controls } — elements the page owns.
   * Returns { render(view) }; the controls and hover state live here.
   */
  function create(opts) {
    const id = ++instances;
    const shown = new Set(CARRIERS.map((c) => c.key));
    let showOffline = true;
    let size = 520;
    let view = null;

    function measure() {
      const w = opts.wrap.clientWidth;
      if (w > 200) size = Math.min(Math.max(w, 320), 720);
    }

    if (typeof ResizeObserver !== 'undefined') {
      new ResizeObserver(() => {
        const before = size;
        measure();
        if (size !== before && view) draw();
      }).observe(opts.wrap);
    }

    function showTip(text) {
      opts.tip.textContent = text;
      opts.tip.hidden = false;
    }

    function hideTip() {
      opts.tip.hidden = true;
    }

    /* the filter row: carrier classes with counts, and offline devices */

    function edgeCounts() {
      const out = {};
      for (const e of (view && view.edges) || []) {
        for (const c of util().participatingCarriers(e.carrier, e.ends)) {
          out[c] = (out[c] || 0) + 1;
        }
      }
      return out;
    }

    function paintControls(nodes) {
      const counts = edgeCounts();
      const offline = nodes.filter((n) => !n.online).length;
      const items = CARRIERS.map((c) => {
        const label = document.createElement('label');
        label.className = 'mesh-filter';
        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.checked = shown.has(c.key);
        cb.dataset.carrier = c.key;
        cb.addEventListener('change', () => {
          if (cb.checked) shown.add(c.key);
          else shown.delete(c.key);
          draw();
        });
        const dot = document.createElement('span');
        dot.className = 'mesh-dot c-' + c.key;
        const count = document.createElement('span');
        count.className = 'muted';
        count.textContent = ' ' + (counts[c.key] || 0);
        label.append(cb, dot, document.createTextNode(c.label), count);
        return label;
      });
      const off = document.createElement('label');
      off.className = 'mesh-filter mesh-filter-offline';
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.checked = showOffline;
      cb.dataset.role = 'offline';
      cb.addEventListener('change', () => {
        showOffline = cb.checked;
        draw();
      });
      off.append(cb, document.createTextNode('Offline devices (' + offline + ')'));
      opts.controls.replaceChildren(...items, off);
    }

    /* the drawing */

    function draw() {
      const svg = opts.svg;
      const radius = Math.max(size / 2 - 96, 40);
      const nodes = nodesFromView(view);
      const placed = layout(nodes, radius);
      // This device stays on the ring even when offline devices are hidden.
      const visible = showOffline ? placed : placed.filter((n) => n.online || n.isSelf);
      const byId = new Map(visible.map((n) => [n.id, n]));

      svg.setAttribute('width', String(size));
      svg.setAttribute('height', String(size));
      svg.setAttribute('viewBox', '0 0 ' + size + ' ' + size);

      const title = svgEl('title');
      title.textContent = 'Private network: this device, the devices it can see, and how they reach each other';
      const defs = svgEl('defs');
      const root = svgEl('g', { transform: 'translate(' + size / 2 + ',' + size / 2 + ')' });
      svgEl('circle', { r: round(radius), class: 'mesh-ring' }, root);

      const spokes = svgEl('g', { class: 'mesh-spokes' }, root);
      for (const n of visible) {
        svgEl(
          'line',
          {
            x1: 0,
            y1: 0,
            x2: round(n.x),
            y2: round(n.y),
            class: 'mesh-spoke' + (n.online ? '' : ' mesh-spoke--off'),
          },
          spokes,
        );
      }

      const edgesG = svgEl('g', { class: 'mesh-edges' }, root);
      let drawnEdges = 0;
      let asymmetric = 0;
      for (const e of (view && view.edges) || []) {
        // Visible when ANY class it takes part in is on: hiding "relay" must
        // not hide the direct half of an asymmetric pair.
        if (!util().participatingCarriers(e.carrier, e.ends).some((c) => shown.has(c))) continue;
        const a = byId.get(e.from);
        const b = byId.get(e.to);
        if (!a || !b) continue;
        const sides = util().edgeSides(e.ends, e.from, e.to);
        const path = svgEl(
          'path',
          {
            d: chordPath(a, b, radius),
            fill: 'none',
            class: 'mesh-edge',
            'stroke-dasharray': e.stalled ? '4 3' : null,
          },
          edgesG,
        );
        if (sides.asymmetric && sides.from && sides.to) {
          asymmetric += 1;
          const gid = 'mesh-grad-' + id + '-' + drawnEdges;
          const g = svgEl(
            'linearGradient',
            {
              id: gid,
              gradientUnits: 'userSpaceOnUse',
              x1: round(a.x),
              y1: round(a.y),
              x2: round(b.x),
              y2: round(b.y),
            },
            defs,
          );
          const from = carrierClass(sides.from.carrier);
          const to = carrierClass(sides.to.carrier);
          svgEl('stop', { offset: '0%', class: 'mesh-stop c-' + from }, g);
          svgEl('stop', { offset: '42%', class: 'mesh-stop c-' + from }, g);
          svgEl('stop', { offset: '58%', class: 'mesh-stop c-' + to }, g);
          svgEl('stop', { offset: '100%', class: 'mesh-stop c-' + to }, g);
          // Inline style, so no class rule can override the gradient.
          path.style.stroke = 'url(#' + gid + ')';
          path.classList.add('is-asym');
        } else {
          path.classList.add('c-' + carrierClass(e.carrier));
        }
        const tip = edgeLines(e, a, b, sides).join('\n');
        path.addEventListener('mouseenter', () => {
          path.classList.add('is-hover');
          showTip(tip);
        });
        path.addEventListener('mouseleave', () => {
          path.classList.remove('is-hover');
          hideTip();
        });
        drawnEdges += 1;
      }

      const centre = svgEl('g', { class: 'mesh-centre' }, root);
      svgEl('circle', { r: 18, class: 'mesh-center' }, centre);
      const centreLabel = svgEl(
        'text',
        { class: 'mesh-center-label', 'text-anchor': 'middle', dy: 34 },
        centre,
      );
      centreLabel.textContent = (view && view.center && view.center.name) || 'roomler.ai';

      const nodesG = svgEl('g', { class: 'mesh-nodes' }, root);
      for (const n of visible) {
        const g = svgEl(
          'g',
          {
            transform: 'translate(' + round(n.x) + ',' + round(n.y) + ')',
            class: 'mesh-node' + (n.isSelf ? ' is-self' : ''),
          },
          nodesG,
        );
        g.dataset.node = n.id;
        if (n.isSelf) svgEl('circle', { r: 13, class: 'mesh-node-ring' }, g);
        const dot = svgEl(
          'circle',
          { r: 8, class: 'mesh-node-dot ' + (n.online ? 'is-online' : 'is-offline') },
          g,
        );
        const left = n.x < -1;
        const label = svgEl(
          'text',
          {
            class: 'mesh-node-label' + (n.isSelf ? ' is-self' : ''),
            'text-anchor': left ? 'end' : 'start',
            dx: left ? -16 : 16,
            dy: 4,
          },
          g,
        );
        label.textContent = n.name;
        const bits = [n.name + (n.isSelf ? ' (this device)' : ''), n.online ? 'online' : 'offline'];
        if (n.relay_home) bits.push('home ' + n.relay_home);
        if (n.version) bits.push('v' + n.version);
        const tip = bits.join(' · ');
        g.addEventListener('mouseenter', () => {
          dot.setAttribute('r', '11');
          showTip(tip);
        });
        g.addEventListener('mouseleave', () => {
          dot.setAttribute('r', '8');
          hideTip();
        });
      }

      svg.replaceChildren(title, defs, root);
      hideTip();
      paintLegend(visible.length, drawnEdges, asymmetric);
    }

    function paintLegend(devices, links, asym) {
      const parts = [
        document.createTextNode(
          devices + (devices === 1 ? ' device' : ' devices') + ' · ' + links + (links === 1 ? ' link' : ' links') + ' shown',
        ),
      ];
      if (asym > 0) {
        const swatch = document.createElement('span');
        swatch.className = 'mesh-asym-swatch';
        swatch.setAttribute('aria-hidden', 'true');
        parts.push(
          document.createTextNode(' · ' + asym + ' asymmetric '),
          swatch,
          document.createTextNode(' two colours = each side’s own carrier'),
        );
      }
      opts.legend.replaceChildren(...parts);
    }

    /** Draw `v` (a MeshView with `enabled: true` and nodes). */
    function render(v) {
      view = v;
      measure();
      paintControls(nodesFromView(view));
      draw();
    }

    return { render };
  }

  window.Roomler.Mesh = { create, layout, chordPath, angleDelta, nodesFromView, CARRIERS };
})();
