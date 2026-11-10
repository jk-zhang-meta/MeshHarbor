# MeshHarbor

One daemon and one web app that replace three products: remote desktop and
control, a private WireGuard mesh, and team collaboration. This file is the
glossary of the words the product, the code and the docs use for one concept.
When several words are in use for one thing, the bold one is canonical.

## Language

### Remote desktop — video

**Codec**:
The bitstream standard a video stream is encoded in: H.264, HEVC (H.265), AV1, VP9. What the controller's browser must be able to decode.
_Avoid_: encoder, format, video type

**Backend**:
The implementation on the controlled host that produces a codec's bitstream: a vendor or OS video engine (NVENC, QSV, AMF, VideoToolbox, VAAPI, D3D12, Vulkan, Media Foundation) or a software library (openh264, libvpx). A property of the host, discovered at runtime, never chosen by the controller.
_Avoid_: encoder, vendor path, hardware, accelerator

**Encoder**:
One codec produced by one backend, named as FFmpeg names it, e.g. `hevc_nvenc`. The unit the agent opens, probes and reports on.
_Avoid_: codec, backend, encoder name (when the codec alone is meant)

**Chroma format**:
How much colour resolution an encoded stream keeps: 4:2:0 (colour at quarter resolution, the video default) or 4:4:4 (full colour resolution, what keeps coloured text and thin lines sharp). A property of the stream that both the encoder and the decoder must support.
_Avoid_: chroma (alone), colour mode, 444 mode, profile

**Cell**:
One codec combined with one chroma format, e.g. HEVC 4:4:4. A cell is available for a session only when the agent has an encoder that produces it and the controller's browser decodes it.
_Avoid_: mode, format, profile, combo, encoder

**Codec picker**:
The controller-side choice of a codec and a chroma format for the next session, as two independent dropdowns. "Auto" in either means the priority decides.
_Avoid_: encoder list, encoder dropdown, codec DDL, transport toggle

**Priority**:
The controller's stated trade-off for a session: latency, balanced, or sharper. It resolves every "Auto" in the codec picker.
_Avoid_: quality mode, preset, profile

**Transport**:
The wire name for the path a codec's frames take to the controller, e.g. `data-channel-hevc`. Kept on the wire for compatibility; `data-channel-vp9-444` carries VP9 in either chroma format.
_Avoid_: codec (when read off a transport name), channel, lane

**Probe**:
The agent's start-up discovery of which encoders and cells the host can open, run in a child process so a faulty driver cannot take the daemon down.
_Avoid_: caps detection, capability scan, encoder test

**Probe cache**:
The remembered answer of the last probe, kept only under the build, hardware, drivers and settings that produced it; a change in any of them re-probes, and an answer that found no hardware is never remembered.
_Avoid_: caps cache file, cached capabilities, hardware cache

### Remote desktop — recording (FR-85)

**Recording**:
A screen captured to a local file by meshharbor's own pipeline, at native resolution — never a copy of the rate-controlled live stream. Encoded at the source, in a pipeline of its own.
_Avoid_: capture, screen grab, screencast, session recording

**Recorder**:
The `meshharbord record` child process that captures, paces and encodes one recording. It runs as the person at the device, never SYSTEM/root while a console user exists.
_Avoid_: capturer (the recorder owns a capturer; they are not the same), encoder, recording engine

**Local recording**:
A recording a person starts at the device, of their own screen.
_Avoid_: self recording, own recording

**Remote recording**:
A recording a controller starts from the browser viewer. The file is written on the controlled device and downloaded on demand over the session's P2P channel; the server never carries it.
_Avoid_: cloud recording, server recording, stream recording

**Recording profile**:
The encoder settings a recording uses — constant quality, a real GOP, native resolution — as opposed to the live stream's network-fit plan.
_Avoid_: quality preset, HQ mode, bitrate ladder (when the recording's own settings are meant)

**Sidecar**:
The `<name>.meshharbor.json` beside a recording: its initiator, device, encoder, dimensions, audio sources, events (locks, gaps, drops) and stop reason. Never content.
_Avoid_: metadata file, manifest, json

**Edit list**:
The `<name>.edit.json` a meshharbor-desktop edit is saved as — contiguous keep / cut / speed-up segments over a recording, read by `meshharbord media export`. Non-destructive.
_Avoid_: EDL (except in code), timeline, project file

**Recording activity**:
What a device **claims** about a recording (prompt outcome, started, stopped, downloaded), stored server-side as facts only, never content; distinct from the server's own authorization decision.
_Avoid_: recording audit, recording log
