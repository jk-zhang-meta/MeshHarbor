// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
// GENERATED from ui/src/utils/mesh.ts by ui/scripts/build-desktop-mesh-util.mjs — do not edit.
// Regenerate: cd ui && bun scripts/build-desktop-mesh-util.mjs
// ui/src/__tests__/utils/desktopMeshUtil.spec.ts fails while this copy is stale.
"use strict";
var RoomlerMesh = (() => {
  var __defProp = Object.defineProperty;
  var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __hasOwnProp = Object.prototype.hasOwnProperty;
  var __export = (target, all) => {
    for (var name in all)
      __defProp(target, name, { get: all[name], enumerable: true });
  };
  var __copyProps = (to, from, except, desc) => {
    if (from && typeof from === "object" || typeof from === "function") {
      for (let key of __getOwnPropNames(from))
        if (!__hasOwnProp.call(to, key) && key !== except)
          __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
    }
    return to;
  };
  var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

  // src/utils/mesh.ts
  var mesh_exports = {};
  __export(mesh_exports, {
    edgeSides: () => edgeSides,
    participatingCarriers: () => participatingCarriers,
    qualifiedCarrier: () => qualifiedCarrier
  });
  function qualifiedCarrier(carrier, relay) {
    if (relay && (carrier === "relay" || carrier === "derp")) return `relay:${relay}`;
    return carrier;
  }
  function edgeSides(ends, fromId, toId) {
    const from = ends == null ? void 0 : ends.find((e) => e.node === fromId);
    const to = ends == null ? void 0 : ends.find((e) => e.node === toId);
    return { from, to, asymmetric: !!(from && to && from.carrier !== to.carrier) };
  }
  function participatingCarriers(merged, ends) {
    const set = /* @__PURE__ */ new Set();
    if (ends == null ? void 0 : ends.length) {
      for (const e of ends) set.add(e.carrier);
    } else {
      set.add(merged);
    }
    return [...set];
  }
  return __toCommonJS(mesh_exports);
})();
