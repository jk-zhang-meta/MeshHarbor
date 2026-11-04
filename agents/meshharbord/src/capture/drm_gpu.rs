// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-107 P3 — the GPU reads the scanout.
//!
//! The CPU path (`drm_backend.rs`) reads the scanout's dma-buf through an
//! uncached mapping: 35 MB a frame at 4K, measured at 27–55 ms on an Apple
//! M2 Pro. The GPU reads the same buffer at full memory bandwidth. Here, EGL
//! imports the buffer (`EGL_EXT_image_dma_buf_import`) and one GLES pass
//! downscales it to exactly the size the pump will encode, converting any of
//! the eight RGB scanout formats (8- and 10-bit, either channel order) to
//! BGRA on the way. The CPU then reads back a frame four times smaller from
//! cached memory. The feasibility prototype measured the whole capture at
//! **1.4 ms** a frame there, 4096×2160 `XR30` to 2048×1080 (#2317).
//!
//! What this module does NOT do, on purpose:
//!
//! - **Link anything.** `libEGL.so.1` and `libGLESv2.so.2` are loaded at
//!   runtime ([`libloading`], as `gpu_clock.rs` loads NVML), so no package
//!   gains a dependency. A host without them (a headless server, a
//!   container, a minimal image) keeps the CPU path, with one log line.
//! - **Use a software renderer.** `llvmpipe`/`softpipe` would do the CPU
//!   path's work more slowly; [`Converter::open`] refuses them.
//! - **Decide what changed.** The idle skip (FR-93 P3d) still samples rows
//!   from the CPU mapping before this runs, and the cursor plane is read as
//!   before; this replaces only the repack.
//! - **Read a tiled scanout.** The CPU path refuses non-linear modifiers at
//!   open, and this path inherits the refusal. EGL could import them (FR-36
//!   P2's deferred detiling) — a later phase, with its own field proof.
//!
//! Everything here runs on the `drm-capture` worker thread, which owns the
//! EGL context for its whole life: an EGL context is current on one thread.
//! The display is the process's ([`Egl`]), brought up once and never torn
//! down; a capture owns its context and nothing more, and retires it unbound
//! ([`Egl::retire`]).

use std::collections::VecDeque;
use std::ffi::{CStr, c_char, c_void};
use std::os::fd::RawFd;
use std::sync::Mutex;

use anyhow::{Result, anyhow, bail};
use libloading::Library;

// ── EGL ───────────────────────────────────────────────────────────────────

type EglDisplay = *mut c_void;
type EglContext = *mut c_void;
type EglImage = *mut c_void;
type EglInt = i32;
type EglBoolean = u32;
type EglEnum = u32;

const EGL_NONE: EglInt = 0x3038;
const EGL_EXTENSIONS: EglInt = 0x3055;
const EGL_OPENGL_ES_API: EglEnum = 0x30A0;
const EGL_CONTEXT_CLIENT_VERSION: EglInt = 0x3098;
const EGL_PLATFORM_SURFACELESS_MESA: EglEnum = 0x31DD;
const EGL_LINUX_DMA_BUF_EXT: EglEnum = 0x3270;
const EGL_WIDTH: EglInt = 0x3057;
const EGL_HEIGHT: EglInt = 0x3056;
const EGL_LINUX_DRM_FOURCC_EXT: EglInt = 0x3271;
const EGL_DMA_BUF_PLANE0_FD_EXT: EglInt = 0x3272;
const EGL_DMA_BUF_PLANE0_OFFSET_EXT: EglInt = 0x3273;
const EGL_DMA_BUF_PLANE0_PITCH_EXT: EglInt = 0x3274;
const EGL_DMA_BUF_PLANE0_MODIFIER_LO_EXT: EglInt = 0x3443;
const EGL_DMA_BUF_PLANE0_MODIFIER_HI_EXT: EglInt = 0x3444;

type FnGetProcAddress = unsafe extern "C" fn(*const c_char) -> *mut c_void;
type FnGetPlatformDisplay = unsafe extern "C" fn(EglEnum, *mut c_void, *const EglInt) -> EglDisplay;
type FnInitialize = unsafe extern "C" fn(EglDisplay, *mut EglInt, *mut EglInt) -> EglBoolean;
type FnQueryString = unsafe extern "C" fn(EglDisplay, EglInt) -> *const c_char;
type FnBindApi = unsafe extern "C" fn(EglEnum) -> EglBoolean;
type FnCreateContext =
    unsafe extern "C" fn(EglDisplay, *mut c_void, EglContext, *const EglInt) -> EglContext;
type FnMakeCurrent =
    unsafe extern "C" fn(EglDisplay, *mut c_void, *mut c_void, EglContext) -> EglBoolean;
type FnDestroyContext = unsafe extern "C" fn(EglDisplay, EglContext) -> EglBoolean;
type FnTerminate = unsafe extern "C" fn(EglDisplay) -> EglBoolean;
type FnGetError = unsafe extern "C" fn() -> EglInt;
type FnCreateImage =
    unsafe extern "C" fn(EglDisplay, EglContext, EglEnum, *mut c_void, *const EglInt) -> EglImage;
type FnDestroyImage = unsafe extern "C" fn(EglDisplay, EglImage) -> EglBoolean;
type FnReleaseThread = unsafe extern "C" fn() -> EglBoolean;

// ── GLES 2 ────────────────────────────────────────────────────────────────

type GlUint = u32;
type GlInt = i32;
type GlEnum = u32;
type GlSizei = i32;

const GL_NO_ERROR: GlEnum = 0;
const GL_TEXTURE_2D: GlEnum = 0x0DE1;
const GL_TEXTURE_MIN_FILTER: GlEnum = 0x2801;
const GL_TEXTURE_MAG_FILTER: GlEnum = 0x2800;
const GL_TEXTURE_WRAP_S: GlEnum = 0x2802;
const GL_TEXTURE_WRAP_T: GlEnum = 0x2803;
const GL_LINEAR: GlInt = 0x2601;
const GL_CLAMP_TO_EDGE: GlInt = 0x812F;
const GL_RGBA: GlEnum = 0x1908;
const GL_UNSIGNED_BYTE: GlEnum = 0x1401;
const GL_FLOAT: GlEnum = 0x1406;
const GL_FRAMEBUFFER: GlEnum = 0x8D40;
const GL_COLOR_ATTACHMENT0: GlEnum = 0x8CE0;
const GL_FRAMEBUFFER_COMPLETE: GlEnum = 0x8CD5;
const GL_VERTEX_SHADER: GlEnum = 0x8B31;
const GL_FRAGMENT_SHADER: GlEnum = 0x8B30;
const GL_COMPILE_STATUS: GlEnum = 0x8B81;
const GL_LINK_STATUS: GlEnum = 0x8B82;
const GL_TRIANGLE_STRIP: GlEnum = 0x0005;
const GL_RENDERER: GlEnum = 0x1F01;
const GL_PACK_ALIGNMENT: GlEnum = 0x0D05;

/// The GLES entry points this module calls, resolved once at open.
struct Gl {
    get_error: unsafe extern "C" fn() -> GlEnum,
    get_string: unsafe extern "C" fn(GlEnum) -> *const u8,
    create_shader: unsafe extern "C" fn(GlEnum) -> GlUint,
    shader_source: unsafe extern "C" fn(GlUint, GlSizei, *const *const c_char, *const GlInt),
    compile_shader: unsafe extern "C" fn(GlUint),
    get_shaderiv: unsafe extern "C" fn(GlUint, GlEnum, *mut GlInt),
    get_shader_info_log: unsafe extern "C" fn(GlUint, GlSizei, *mut GlSizei, *mut c_char),
    create_program: unsafe extern "C" fn() -> GlUint,
    attach_shader: unsafe extern "C" fn(GlUint, GlUint),
    bind_attrib_location: unsafe extern "C" fn(GlUint, GlUint, *const c_char),
    link_program: unsafe extern "C" fn(GlUint),
    get_programiv: unsafe extern "C" fn(GlUint, GlEnum, *mut GlInt),
    use_program: unsafe extern "C" fn(GlUint),
    get_uniform_location: unsafe extern "C" fn(GlUint, *const c_char) -> GlInt,
    uniform1i: unsafe extern "C" fn(GlInt, GlInt),
    uniform2f: unsafe extern "C" fn(GlInt, f32, f32),
    vertex_attrib_pointer: unsafe extern "C" fn(GlUint, GlInt, GlEnum, u8, GlSizei, *const c_void),
    enable_vertex_attrib_array: unsafe extern "C" fn(GlUint),
    gen_textures: unsafe extern "C" fn(GlSizei, *mut GlUint),
    delete_textures: unsafe extern "C" fn(GlSizei, *const GlUint),
    bind_texture: unsafe extern "C" fn(GlEnum, GlUint),
    tex_image_2d: unsafe extern "C" fn(
        GlEnum,
        GlInt,
        GlInt,
        GlSizei,
        GlSizei,
        GlInt,
        GlEnum,
        GlEnum,
        *const c_void,
    ),
    tex_parameteri: unsafe extern "C" fn(GlEnum, GlEnum, GlInt),
    gen_framebuffers: unsafe extern "C" fn(GlSizei, *mut GlUint),
    bind_framebuffer: unsafe extern "C" fn(GlEnum, GlUint),
    framebuffer_texture_2d: unsafe extern "C" fn(GlEnum, GlEnum, GlEnum, GlUint, GlInt),
    check_framebuffer_status: unsafe extern "C" fn(GlEnum) -> GlEnum,
    viewport: unsafe extern "C" fn(GlInt, GlInt, GlSizei, GlSizei),
    draw_arrays: unsafe extern "C" fn(GlEnum, GlInt, GlSizei),
    pixel_storei: unsafe extern "C" fn(GlEnum, GlInt),
    read_pixels: unsafe extern "C" fn(GlInt, GlInt, GlSizei, GlSizei, GlEnum, GlEnum, *mut c_void),
    egl_image_target_texture_2d: unsafe extern "C" fn(GlEnum, *mut c_void),
}

/// FR-107 P3 — kill switch `ROOMLERD_DRM_GPU=0`: the CPU reads the scanout,
/// as before P3.
pub fn enabled() -> bool {
    tunnel_core::env::flag("DRM_GPU", true)
}

/// One dma-buf to import: the primary plane's framebuffer, as `GETFB2`
/// described it. `fd` is borrowed: EGL takes its own reference to the buffer.
pub struct Source {
    pub fd: RawFd,
    pub width: u32,
    pub height: u32,
    pub fourcc: u32,
    pub offset: u32,
    pub pitch: u32,
    /// `None` for a framebuffer created without modifiers (linear by
    /// definition); the import then names none either.
    pub modifier: Option<u64>,
}

/// The attribute list `eglCreateImageKHR` takes for `src`.
fn import_attrs(src: &Source) -> Vec<EglInt> {
    let mut a = vec![
        EGL_WIDTH,
        src.width as EglInt,
        EGL_HEIGHT,
        src.height as EglInt,
        EGL_LINUX_DRM_FOURCC_EXT,
        src.fourcc as EglInt,
        EGL_DMA_BUF_PLANE0_FD_EXT,
        src.fd,
        EGL_DMA_BUF_PLANE0_OFFSET_EXT,
        src.offset as EglInt,
        EGL_DMA_BUF_PLANE0_PITCH_EXT,
        src.pitch as EglInt,
    ];
    if let Some(m) = src.modifier {
        a.extend([
            EGL_DMA_BUF_PLANE0_MODIFIER_LO_EXT,
            (m & 0xffff_ffff) as u32 as EglInt,
            EGL_DMA_BUF_PLANE0_MODIFIER_HI_EXT,
            (m >> 32) as u32 as EglInt,
        ]);
    }
    a.push(EGL_NONE);
    a
}

/// How the shader samples one output pixel: `n`×`n` bilinear taps spread over
/// the source footprint the pixel covers, so every source pixel contributes
/// at any ratio up to 8:1. Each bilinear tap already averages a 2×2 block, so
/// `n = ⌈ratio / 2⌉` (1 for a copy, 2 for the 4K → 1080p case), at most 4.
/// Returns `(n, step, first)`, `step` and `first` in texture coordinates.
fn taps(src: (u32, u32), out: (u32, u32)) -> (i32, (f32, f32), (f32, f32)) {
    let ratio = f64::max(
        f64::from(src.0) / f64::from(out.0.max(1)),
        f64::from(src.1) / f64::from(out.1.max(1)),
    );
    let n = (ratio / 2.0).ceil().clamp(1.0, 4.0) as i32;
    let step = (
        (1.0 / (f64::from(n) * f64::from(out.0.max(1)))) as f32,
        (1.0 / (f64::from(n) * f64::from(out.1.max(1)))) as f32,
    );
    let half = (n - 1) as f32 / 2.0;
    (n, step, (-half * step.0, -half * step.1))
}

const VERTEX: &CStr = c"attribute vec2 pos; varying vec2 uv;
void main() { uv = pos * 0.5 + 0.5; gl_Position = vec4(pos, 0.0, 1.0); }";

/// Up to 4×4 bilinear taps per output pixel ([`taps`]), averaged, then
/// written B,G,R,A: a plain RGBA readback then lands in the `Frame`
/// contract's BGRA byte order. The scanout's channel order and depth are
/// EGL's business: the import names the fourcc, and a sample is always
/// (r, g, b, a).
const FRAGMENT: &CStr = c"precision highp float;
varying vec2 uv;
uniform sampler2D tex;
uniform vec2 step;
uniform vec2 first;
uniform int n;
void main() {
  vec4 sum = vec4(0.0);
  for (int y = 0; y < 4; y++) {
    if (y >= n) break;
    for (int x = 0; x < 4; x++) {
      if (x >= n) break;
      sum += texture2D(tex, uv + first + vec2(float(x), float(y)) * step);
    }
  }
  sum /= float(n * n);
  gl_FragColor = vec4(sum.b, sum.g, sum.r, 1.0);
}";

/// The full-screen quad, as two triangles of a strip. Client-side vertex
/// data is enough in GLES 2, and it must outlive every draw: a `static`.
static QUAD: [f32; 8] = [-1.0, -1.0, 1.0, -1.0, -1.0, 1.0, 1.0, 1.0];

/// How many imported buffers stay cached: a compositor cycles through two or
/// three, and each entry holds a reference that keeps its buffer alive.
const IMAGES: usize = 4;

/// An imported scanout buffer, keyed as the CPU path keys its mapping
/// (framebuffer id + dma-buf inode, FR-93 P3f).
struct Imported {
    key: (u32, u64),
    image: EglImage,
    texture: GlUint,
}

/// The GPU path: an EGL context of its own on the process's display, the
/// imported buffers, and the target it renders into.
pub struct Converter {
    egl: &'static Egl,
    context: EglContext,
    gl: Gl,
    program: GlUint,
    u_tex: GlInt,
    u_step: GlInt,
    u_first: GlInt,
    u_n: GlInt,
    fbo: GlUint,
    target: GlUint,
    target_size: (u32, u32),
    images: VecDeque<Imported>,
    /// The renderer, for the log line that says the GPU path is in use.
    pub renderer: String,
}

/// Look `name` up through `eglGetProcAddress`, then the library itself.
///
/// # Safety
/// `T` must be the function pointer type of `name`.
unsafe fn proc<T: Copy>(gpa: FnGetProcAddress, lib: &Library, name: &CStr) -> Result<T> {
    // SAFETY: `name` is NUL-terminated; a non-null result is the entry point.
    let p = unsafe { gpa(name.as_ptr()) };
    if !p.is_null() {
        // SAFETY: the caller names the type; a fn pointer is pointer-sized.
        return Ok(unsafe { std::mem::transmute_copy::<*mut c_void, T>(&p) });
    }
    // SAFETY: as above, through the loader.
    unsafe { lib.get::<T>(name.to_bytes_with_nul()) }
        .map(|s| *s)
        .map_err(|e| anyhow!("{}: {e}", name.to_string_lossy()))
}

/// The process's EGL: both libraries, the entry points, and the surfaceless
/// display. The first capture that reaches for the GPU brings it up, and it
/// stays up for the life of the process.
///
/// ⚠️ **Never terminated, never unloaded.** EGL hands every caller in a
/// process the same display, so a capture that terminated it on its way out
/// would pull it from under any capture still running — a second viewer, or a
/// pump restart whose new capture opened before the old worker exited. That
/// capture would lose its imports and fall back to the CPU without a word
/// about why. A capture owns its context and nothing more ([`Egl::retire`]).
struct Egl {
    _egl_lib: Library,
    gl_lib: Library,
    gpa: FnGetProcAddress,
    display: EglDisplay,
    bind_api: FnBindApi,
    create_context: FnCreateContext,
    make_current: FnMakeCurrent,
    destroy_context: FnDestroyContext,
    release_thread: FnReleaseThread,
    get_error: FnGetError,
    create_image: FnCreateImage,
    destroy_image: FnDestroyImage,
}

// SAFETY: EGL's entry points may be called from any thread, and a display is
// one handle for the whole process. What EGL keeps per thread (the bound API,
// the current context) each capture sets on its own worker thread.
unsafe impl Send for Egl {}
// SAFETY: as above; nothing in an `Egl` changes after `load`.
unsafe impl Sync for Egl {}

/// The process's [`Egl`], once one came up. A failure is not kept: the next
/// capture tries again.
static EGL: Mutex<Option<&'static Egl>> = Mutex::new(None);

impl Egl {
    /// The process's EGL, brought up by the first caller.
    fn get() -> Result<&'static Egl> {
        let mut slot = EGL.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(egl) = *slot {
            return Ok(egl);
        }
        let egl: &'static Egl = Box::leak(Box::new(Self::load()?));
        *slot = Some(egl);
        Ok(egl)
    }

    fn load() -> Result<Self> {
        // SAFETY: loading the system's EGL and GLES by their sonames; their
        // constructors are the GL vendor's, as in every GL program.
        let egl_lib =
            unsafe { Library::new("libEGL.so.1") }.map_err(|e| anyhow!("libEGL.so.1: {e}"))?;
        // SAFETY: as above.
        let gl_lib = unsafe { Library::new("libGLESv2.so.2") }
            .map_err(|e| anyhow!("libGLESv2.so.2: {e}"))?;
        // SAFETY: the signature is eglGetProcAddress's.
        let gpa: FnGetProcAddress =
            unsafe { egl_lib.get::<FnGetProcAddress>(b"eglGetProcAddress\0") }
                .map(|s| *s)
                .map_err(|e| anyhow!("eglGetProcAddress: {e}"))?;
        // SAFETY (each line below): the type named is the entry point's own.
        let get_platform_display: FnGetPlatformDisplay =
            unsafe { proc(gpa, &egl_lib, c"eglGetPlatformDisplayEXT") }?;
        let initialize: FnInitialize = unsafe { proc(gpa, &egl_lib, c"eglInitialize") }?;
        let query_string: FnQueryString = unsafe { proc(gpa, &egl_lib, c"eglQueryString") }?;
        let terminate: FnTerminate = unsafe { proc(gpa, &egl_lib, c"eglTerminate") }?;
        let get_error: FnGetError = unsafe { proc(gpa, &egl_lib, c"eglGetError") }?;
        let bind_api: FnBindApi = unsafe { proc(gpa, &egl_lib, c"eglBindAPI") }?;
        let create_context: FnCreateContext = unsafe { proc(gpa, &egl_lib, c"eglCreateContext") }?;
        let make_current: FnMakeCurrent = unsafe { proc(gpa, &egl_lib, c"eglMakeCurrent") }?;
        let destroy_context: FnDestroyContext =
            unsafe { proc(gpa, &egl_lib, c"eglDestroyContext") }?;
        let release_thread: FnReleaseThread = unsafe { proc(gpa, &egl_lib, c"eglReleaseThread") }?;
        let create_image: FnCreateImage = unsafe { proc(gpa, &egl_lib, c"eglCreateImageKHR") }?;
        let destroy_image: FnDestroyImage = unsafe { proc(gpa, &egl_lib, c"eglDestroyImageKHR") }?;

        // The platform: Mesa's surfaceless one renders off-screen on a render
        // node, with no window system, no GBM and no display server — what a
        // root daemon outside every session has.
        // SAFETY: EGL_NO_DISPLAY asks for the client extensions.
        let client_ext = unsafe { query_string(std::ptr::null_mut(), EGL_EXTENSIONS) };
        let client_ext = cstr(client_ext);
        if !client_ext.contains("EGL_MESA_platform_surfaceless") {
            bail!("EGL has no surfaceless platform (not Mesa?)");
        }
        // SAFETY: the surfaceless platform takes EGL_DEFAULT_DISPLAY (null).
        let display = unsafe {
            get_platform_display(
                EGL_PLATFORM_SURFACELESS_MESA,
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        if display.is_null() {
            bail!("eglGetPlatformDisplay(surfaceless) gave no display");
        }
        let (mut major, mut minor) = (0, 0);
        // SAFETY: out-pointers to locals.
        if unsafe { initialize(display, &mut major, &mut minor) } == 0 {
            bail!("eglInitialize failed: {:#x}", unsafe { get_error() });
        }
        // SAFETY: an initialised display.
        let ext = cstr(unsafe { query_string(display, EGL_EXTENSIONS) });
        for need in [
            "EGL_EXT_image_dma_buf_import",
            "EGL_KHR_surfaceless_context",
            "EGL_KHR_no_config_context",
        ] {
            if !ext.split_ascii_whitespace().any(|e| e == need) {
                // SAFETY: tearing down what this call initialised. Nothing
                // else holds the display: it is published only on success.
                unsafe { terminate(display) };
                bail!("EGL lacks {need}");
            }
        }
        Ok(Self {
            _egl_lib: egl_lib,
            gl_lib,
            gpa,
            display,
            bind_api,
            create_context,
            make_current,
            destroy_context,
            release_thread,
            get_error,
            create_image,
            destroy_image,
        })
    }

    /// Retire a capture's context, on the thread it is current on.
    ///
    /// ⚠️ **Unbind first.** EGL frees a destroyed context only once it is no
    /// longer current, and a worker thread that exits with its context still
    /// bound never unbinds it. Destroying it bound leaked the context for the
    /// life of the process: 2.8 MB a capture on an M2 Pro, 53 → 191 MB over
    /// 50 captures, against flat with the unbind (#2317).
    fn retire(&self, context: EglContext) {
        // SAFETY: `context` is current on this thread, made so by `open`.
        unsafe {
            (self.make_current)(
                self.display,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            (self.destroy_context)(self.display, context);
            (self.release_thread)();
        }
    }
}

impl Converter {
    /// A context on the process's EGL display ([`Egl`]), and the one program
    /// this module draws with. Any failure means "no GPU path here", and the
    /// caller keeps the CPU path.
    pub fn open() -> Result<Self> {
        let egl = Egl::get()?;
        // SAFETY: plain enum. The bound API is per thread, so every capture
        // binds it on its own worker.
        unsafe { (egl.bind_api)(EGL_OPENGL_ES_API) };
        let attrs = [EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE];
        // SAFETY: EGL_NO_CONFIG_KHR (null) with EGL_KHR_no_config_context.
        let context = unsafe {
            (egl.create_context)(
                egl.display,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                attrs.as_ptr(),
            )
        };
        if context.is_null() {
            bail!("eglCreateContext failed: {:#x}", unsafe {
                (egl.get_error)()
            });
        }
        // SAFETY: no surfaces, with EGL_KHR_surfaceless_context; this thread
        // owns the context from here on.
        if unsafe {
            (egl.make_current)(
                egl.display,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                context,
            )
        } == 0
        {
            let err = unsafe { (egl.get_error)() };
            // SAFETY: a context that never became current is freed as it is
            // destroyed.
            unsafe {
                (egl.destroy_context)(egl.display, context);
                (egl.release_thread)();
            }
            bail!("eglMakeCurrent failed: {err:#x}");
        }

        // SAFETY: a current context; every entry point resolved by its name.
        let gl = match unsafe { Gl::load(egl.gpa, &egl.gl_lib) } {
            Ok(gl) => gl,
            Err(e) => {
                egl.retire(context);
                return Err(e);
            }
        };

        // SAFETY: a current context.
        let renderer = cstr(unsafe { (gl.get_string)(GL_RENDERER) }.cast());
        let lower = renderer.to_ascii_lowercase();
        if ["llvmpipe", "softpipe", "swrast", "software"]
            .iter()
            .any(|s| lower.contains(s))
        {
            egl.retire(context);
            bail!("the renderer is software ({renderer}): the CPU path is faster");
        }

        let mut conv = Self {
            egl,
            context,
            gl,
            program: 0,
            u_tex: -1,
            u_step: -1,
            u_first: -1,
            u_n: -1,
            fbo: 0,
            target: 0,
            target_size: (0, 0),
            images: VecDeque::new(),
            renderer,
        };
        // From here `Drop` retires the context, whatever fails.
        conv.build_program()?;
        Ok(conv)
    }
}

impl Gl {
    /// Every GLES entry point this module calls, through `eglGetProcAddress`
    /// first and the library second.
    ///
    /// # Safety
    /// A GLES context must be current on this thread.
    unsafe fn load(gpa: FnGetProcAddress, gl_lib: &Library) -> Result<Self> {
        // SAFETY (each line below): the type named is the entry point's own.
        unsafe {
            Ok(Gl {
                get_error: proc(gpa, gl_lib, c"glGetError")?,
                get_string: proc(gpa, gl_lib, c"glGetString")?,
                create_shader: proc(gpa, gl_lib, c"glCreateShader")?,
                shader_source: proc(gpa, gl_lib, c"glShaderSource")?,
                compile_shader: proc(gpa, gl_lib, c"glCompileShader")?,
                get_shaderiv: proc(gpa, gl_lib, c"glGetShaderiv")?,
                get_shader_info_log: proc(gpa, gl_lib, c"glGetShaderInfoLog")?,
                create_program: proc(gpa, gl_lib, c"glCreateProgram")?,
                attach_shader: proc(gpa, gl_lib, c"glAttachShader")?,
                bind_attrib_location: proc(gpa, gl_lib, c"glBindAttribLocation")?,
                link_program: proc(gpa, gl_lib, c"glLinkProgram")?,
                get_programiv: proc(gpa, gl_lib, c"glGetProgramiv")?,
                use_program: proc(gpa, gl_lib, c"glUseProgram")?,
                get_uniform_location: proc(gpa, gl_lib, c"glGetUniformLocation")?,
                uniform1i: proc(gpa, gl_lib, c"glUniform1i")?,
                uniform2f: proc(gpa, gl_lib, c"glUniform2f")?,
                vertex_attrib_pointer: proc(gpa, gl_lib, c"glVertexAttribPointer")?,
                enable_vertex_attrib_array: proc(gpa, gl_lib, c"glEnableVertexAttribArray")?,
                gen_textures: proc(gpa, gl_lib, c"glGenTextures")?,
                delete_textures: proc(gpa, gl_lib, c"glDeleteTextures")?,
                bind_texture: proc(gpa, gl_lib, c"glBindTexture")?,
                tex_image_2d: proc(gpa, gl_lib, c"glTexImage2D")?,
                tex_parameteri: proc(gpa, gl_lib, c"glTexParameteri")?,
                gen_framebuffers: proc(gpa, gl_lib, c"glGenFramebuffers")?,
                bind_framebuffer: proc(gpa, gl_lib, c"glBindFramebuffer")?,
                framebuffer_texture_2d: proc(gpa, gl_lib, c"glFramebufferTexture2D")?,
                check_framebuffer_status: proc(gpa, gl_lib, c"glCheckFramebufferStatus")?,
                viewport: proc(gpa, gl_lib, c"glViewport")?,
                draw_arrays: proc(gpa, gl_lib, c"glDrawArrays")?,
                pixel_storei: proc(gpa, gl_lib, c"glPixelStorei")?,
                read_pixels: proc(gpa, gl_lib, c"glReadPixels")?,
                egl_image_target_texture_2d: proc(gpa, gl_lib, c"glEGLImageTargetTexture2DOES")?,
            })
        }
    }
}

impl Converter {
    fn compile(&self, kind: GlEnum, src: &CStr) -> Result<GlUint> {
        let gl = &self.gl;
        // SAFETY: a current context; `src` outlives the call.
        unsafe {
            let s = (gl.create_shader)(kind);
            let ptr = src.as_ptr();
            (gl.shader_source)(s, 1, &ptr, std::ptr::null());
            (gl.compile_shader)(s);
            let mut ok = 0;
            (gl.get_shaderiv)(s, GL_COMPILE_STATUS, &mut ok);
            if ok == 0 {
                let mut log = [0 as c_char; 512];
                (gl.get_shader_info_log)(
                    s,
                    log.len() as GlSizei,
                    std::ptr::null_mut(),
                    log.as_mut_ptr(),
                );
                bail!("shader: {}", cstr(log.as_ptr()));
            }
            Ok(s)
        }
    }

    fn build_program(&mut self) -> Result<()> {
        let vs = self.compile(GL_VERTEX_SHADER, VERTEX)?;
        let fs = self.compile(GL_FRAGMENT_SHADER, FRAGMENT)?;
        let gl = &self.gl;
        // SAFETY: a current context; the shaders were just compiled.
        unsafe {
            let p = (gl.create_program)();
            (gl.attach_shader)(p, vs);
            (gl.attach_shader)(p, fs);
            (gl.bind_attrib_location)(p, 0, c"pos".as_ptr());
            (gl.link_program)(p);
            let mut ok = 0;
            (gl.get_programiv)(p, GL_LINK_STATUS, &mut ok);
            if ok == 0 {
                bail!("program did not link");
            }
            (gl.use_program)(p);
            self.u_tex = (gl.get_uniform_location)(p, c"tex".as_ptr());
            self.u_step = (gl.get_uniform_location)(p, c"step".as_ptr());
            self.u_first = (gl.get_uniform_location)(p, c"first".as_ptr());
            self.u_n = (gl.get_uniform_location)(p, c"n".as_ptr());
            (gl.vertex_attrib_pointer)(0, 2, GL_FLOAT, 0, 0, QUAD.as_ptr().cast());
            (gl.enable_vertex_attrib_array)(0);
            (gl.uniform1i)(self.u_tex, 0);
            (gl.gen_framebuffers)(1, &mut self.fbo);
            (gl.pixel_storei)(GL_PACK_ALIGNMENT, 4);
            self.program = p;
        }
        Ok(())
    }

    /// The texture of `src`, imported on first sight and cached by `key`.
    fn texture_for(&mut self, key: (u32, u64), src: &Source) -> Result<GlUint> {
        if let Some(i) = self.images.iter().position(|e| e.key == key) {
            // Most recently used last, so the front is what goes first.
            let e = self.images.remove(i).expect("position is in range");
            let t = e.texture;
            self.images.push_back(e);
            return Ok(t);
        }
        let attrs = import_attrs(src);
        // SAFETY: an initialised display; `attrs` is EGL_NONE-terminated and
        // names a dma-buf fd that is open for the call.
        let image = unsafe {
            (self.egl.create_image)(
                self.egl.display,
                std::ptr::null_mut(),
                EGL_LINUX_DMA_BUF_EXT,
                std::ptr::null_mut(),
                attrs.as_ptr(),
            )
        };
        if image.is_null() {
            bail!("eglCreateImage(dma-buf) failed: {:#x}", unsafe {
                (self.egl.get_error)()
            });
        }
        let gl = &self.gl;
        let mut texture = 0;
        // SAFETY: a current context; `image` was just created.
        unsafe {
            (gl.gen_textures)(1, &mut texture);
            (gl.bind_texture)(GL_TEXTURE_2D, texture);
            (gl.egl_image_target_texture_2d)(GL_TEXTURE_2D, image);
            (gl.tex_parameteri)(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
            (gl.tex_parameteri)(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
            (gl.tex_parameteri)(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
            (gl.tex_parameteri)(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
            let err = (gl.get_error)();
            if err != GL_NO_ERROR {
                (gl.delete_textures)(1, &texture);
                (self.egl.destroy_image)(self.egl.display, image);
                bail!("binding the imported buffer failed: GL error {err:#x}");
            }
        }
        self.images.push_back(Imported {
            key,
            image,
            texture,
        });
        while self.images.len() > IMAGES {
            if let Some(old) = self.images.pop_front() {
                self.release(old);
            }
        }
        Ok(texture)
    }

    fn release(&self, e: Imported) {
        // SAFETY: deleting what `texture_for` created, on its context.
        unsafe {
            (self.gl.delete_textures)(1, &e.texture);
            (self.egl.destroy_image)(self.egl.display, e.image);
        }
    }

    /// The render target, (re)made at `size`.
    fn target_at(&mut self, size: (u32, u32)) -> Result<()> {
        if self.target_size == size && self.target != 0 {
            return Ok(());
        }
        let gl = &self.gl;
        // SAFETY: a current context.
        unsafe {
            if self.target != 0 {
                (gl.delete_textures)(1, &self.target);
            }
            let mut t = 0;
            (gl.gen_textures)(1, &mut t);
            (gl.bind_texture)(GL_TEXTURE_2D, t);
            (gl.tex_image_2d)(
                GL_TEXTURE_2D,
                0,
                GL_RGBA as GlInt,
                size.0 as GlSizei,
                size.1 as GlSizei,
                0,
                GL_RGBA,
                GL_UNSIGNED_BYTE,
                std::ptr::null(),
            );
            (gl.bind_framebuffer)(GL_FRAMEBUFFER, self.fbo);
            (gl.framebuffer_texture_2d)(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, t, 0);
            let status = (gl.check_framebuffer_status)(GL_FRAMEBUFFER);
            self.target = t;
            if status != GL_FRAMEBUFFER_COMPLETE {
                self.target_size = (0, 0);
                bail!("the render target is incomplete: {status:#x}");
            }
        }
        self.target_size = size;
        Ok(())
    }

    /// `src`, scaled to `out` and converted to BGRA: `out.0 × out.1 × 4`
    /// tightly packed bytes, top row first.
    pub fn convert(&mut self, key: (u32, u64), src: &Source, out: (u32, u32)) -> Result<Vec<u8>> {
        if out.0 == 0 || out.1 == 0 {
            bail!("empty output size");
        }
        let texture = self.texture_for(key, src)?;
        self.render(texture, (src.width, src.height), out)
    }

    /// One draw of `texture` (a `src`-sized image) at `out`, read back.
    fn render(&mut self, texture: GlUint, src: (u32, u32), out: (u32, u32)) -> Result<Vec<u8>> {
        self.target_at(out)?;
        let (n, step, first) = taps(src, out);
        let mut data = vec![0u8; out.0 as usize * out.1 as usize * 4];
        let gl = &self.gl;
        // SAFETY: a current context; `data` holds exactly the pixels read.
        unsafe {
            (gl.bind_framebuffer)(GL_FRAMEBUFFER, self.fbo);
            (gl.bind_texture)(GL_TEXTURE_2D, texture);
            (gl.viewport)(0, 0, out.0 as GlSizei, out.1 as GlSizei);
            (gl.uniform1i)(self.u_n, n);
            (gl.uniform2f)(self.u_step, step.0, step.1);
            (gl.uniform2f)(self.u_first, first.0, first.1);
            (gl.draw_arrays)(GL_TRIANGLE_STRIP, 0, 4);
            (gl.read_pixels)(
                0,
                0,
                out.0 as GlSizei,
                out.1 as GlSizei,
                GL_RGBA,
                GL_UNSIGNED_BYTE,
                data.as_mut_ptr().cast(),
            );
            let err = (gl.get_error)();
            if err != GL_NO_ERROR {
                bail!("the GPU pass failed: GL error {err:#x}");
            }
        }
        Ok(data)
    }
}

impl Drop for Converter {
    fn drop(&mut self) {
        // The imports belong to the display, not the context: they would
        // outlive it unless destroyed.
        while let Some(e) = self.images.pop_front() {
            self.release(e);
        }
        // The program, the framebuffer and the render target go with the
        // context; the display stays the process's.
        self.egl.retire(self.context);
    }
}

/// A C string from EGL or GL as owned text; empty for a null pointer.
fn cstr(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: EGL and GL return NUL-terminated static strings.
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The import names every plane-0 attribute, the modifier only when the
    /// framebuffer had one, split into its two halves, and ends in EGL_NONE.
    #[test]
    fn the_import_names_the_buffer_as_getfb2_described_it() {
        let src = Source {
            fd: 7,
            width: 4096,
            height: 2160,
            fourcc: 0x3033_5258, // XR30
            offset: 0,
            pitch: 16384,
            modifier: None,
        };
        let a = import_attrs(&src);
        assert_eq!(a.last(), Some(&EGL_NONE));
        assert!(a.windows(2).any(|w| w == [EGL_DMA_BUF_PLANE0_FD_EXT, 7]));
        assert!(
            a.windows(2)
                .any(|w| w == [EGL_DMA_BUF_PLANE0_PITCH_EXT, 16384])
        );
        assert!(!a.contains(&EGL_DMA_BUF_PLANE0_MODIFIER_LO_EXT));
        let tiled = import_attrs(&Source {
            modifier: Some(0x0100_0000_0000_0004),
            ..src
        });
        assert!(
            tiled
                .windows(2)
                .any(|w| w == [EGL_DMA_BUF_PLANE0_MODIFIER_LO_EXT, 4])
        );
        assert!(
            tiled
                .windows(2)
                .any(|w| w == [EGL_DMA_BUF_PLANE0_MODIFIER_HI_EXT, 0x0100_0000])
        );
    }

    /// One tap for a copy, a 2×2 grid for the 4K → 1080p case, never more
    /// than 4×4, and the grid centred on the output pixel.
    #[test]
    fn the_taps_cover_the_footprint() {
        let (n, _, first) = taps((1920, 1080), (1920, 1080));
        assert_eq!(n, 1);
        assert_eq!(first, (0.0, 0.0));
        let (n, step, first) = taps((4096, 2160), (1920, 1012));
        assert_eq!(n, 2);
        assert!((first.0 + step.0 / 2.0).abs() < 1e-9);
        assert!((first.1 + step.1 / 2.0).abs() < 1e-9);
        assert_eq!(taps((7680, 4320), (640, 360)).0, 4);
    }

    /// A capture's teardown leaves nothing behind. Thirty captures, each on a
    /// thread of its own as a `drm-capture` worker is, each drawing and
    /// reading back one frame at the 4K → half size, and the process's
    /// resident memory ends where the warm-up left it. Destroying the context
    /// while it was still current leaked it: 2.8 MB a capture on an M2 Pro,
    /// so ~84 MB here (#2317). Run it alone, on a host with a GPU:
    /// `cargo test -p meshharbord --lib --features full -- --ignored --test-threads=1 a_capture_leaks_nothing`
    #[test]
    #[ignore = "needs a GPU render node and Mesa's surfaceless EGL"]
    fn a_capture_leaks_nothing_when_it_ends() {
        fn capture() {
            std::thread::spawn(|| {
                let mut c = Converter::open().expect("a GPU path on this host");
                // Texture 0 samples as black: the draw and the readback are
                // the capture's, without a scanout to import.
                let frame = c.render(0, (4096, 2160), (2048, 1080)).expect("one draw");
                assert_eq!(frame.len(), 2048 * 1080 * 4);
            })
            .join()
            .expect("the capture thread");
        }
        fn rss_kb() -> u64 {
            std::fs::read_to_string("/proc/self/status")
                .expect("procfs")
                .lines()
                .find_map(|l| l.strip_prefix("VmRSS:"))
                .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
                .expect("VmRSS")
        }
        // The first captures load the driver and compile the shaders.
        capture();
        capture();
        let before = rss_kb();
        for _ in 0..30 {
            capture();
        }
        let grown = rss_kb().saturating_sub(before);
        assert!(
            grown < 12 * 1024,
            "resident memory grew {grown} kB over 30 captures"
        );
    }
}
