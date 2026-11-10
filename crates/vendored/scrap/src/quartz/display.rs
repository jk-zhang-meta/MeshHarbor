use super::ffi::*;
use std::mem;

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
#[repr(C)]
pub struct Display(u32);

impl Display {
    pub fn primary() -> Display {
        Display(unsafe { CGMainDisplayID() })
    }

    pub fn online() -> Result<Vec<Display>, CGError> {
        unsafe {
            let mut arr: [u32; 16] = mem::uninitialized();
            let mut len: u32 = 0;

            match CGGetOnlineDisplayList(16, arr.as_mut_ptr(), &mut len) {
                CGError::Success => (),
                x => return Err(x)
            }

            let mut res = Vec::with_capacity(16);
            for i in 0..len as usize {
                res.push(Display(*arr.get_unchecked(i)));
            }
            Ok(res)
        }
    }

    pub fn id(self) -> u32 {
        self.0
    }

    pub fn width(self) -> usize {
        unsafe { CGDisplayPixelsWide(self.0) }
    }

    pub fn height(self) -> usize {
        unsafe { CGDisplayPixelsHigh(self.0) }
    }

    /// MESHHARBOR PATCH: the display's true width in PIXELS.
    ///
    /// [`Display::width`] is named for pixels but returns POINTS. Both are
    /// kept, because the distinction is load-bearing: a capture stream wants
    /// PIXELS (else a Retina panel streams at a quarter of its real detail),
    /// while pointer injection wants POINTS (that is the coordinate space
    /// `CGWarpMouseCursorPosition` and friends live in). Mixing them up puts
    /// the cursor at half-coordinates or the picture at half-resolution.
    pub fn pixel_width(self) -> usize {
        self.pixel_size().0
    }

    /// MESHHARBOR PATCH: the display's true height in PIXELS. See
    /// [`Display::pixel_width`].
    pub fn pixel_height(self) -> usize {
        self.pixel_size().1
    }

    /// Both pixel dimensions in one mode copy.
    ///
    /// Falls back to the POINT size whenever the mode is unavailable or
    /// reports zero, so a caller always receives usable dimensions — a
    /// degraded-but-working capture beats a zero-sized stream.
    fn pixel_size(self) -> (usize, usize) {
        unsafe {
            let mode = CGDisplayCopyDisplayMode(self.0);
            if mode.is_null() {
                return (self.width(), self.height());
            }
            let w = CGDisplayModeGetPixelWidth(mode);
            let h = CGDisplayModeGetPixelHeight(mode);
            // *Copy* convention — we own this and must release it, on every
            // path. Done before the zero-check so the early return can't leak.
            CGDisplayModeRelease(mode);
            if w == 0 || h == 0 {
                (self.width(), self.height())
            } else {
                (w, h)
            }
        }
    }

    pub fn is_builtin(self) -> bool {
        unsafe { CGDisplayIsBuiltin(self.0) != 0 }
    }

    pub fn is_primary(self) -> bool {
        unsafe { CGDisplayIsMain(self.0) != 0 }
    }

    pub fn is_active(self) -> bool {
        unsafe { CGDisplayIsActive(self.0) != 0 }
    }

    pub fn is_online(self) -> bool {
        unsafe { CGDisplayIsOnline(self.0) != 0 }
    }
}
