use super::ffi::*;
use std::{ops, ptr, slice};

pub struct Frame {
    surface: IOSurfaceRef,
    inner: &'static [u8],
    // MESHHARBOR PATCH: see `bytes_per_row` below.
    bytes_per_row: usize
}

impl Frame {
    pub unsafe fn new(surface: IOSurfaceRef) -> Frame {
        CFRetain(surface);
        IOSurfaceIncrementUseCount(surface);

        IOSurfaceLock(
            surface,
            SURFACE_LOCK_READ_ONLY,
            ptr::null_mut()
        );

        let inner = slice::from_raw_parts(
            IOSurfaceGetBaseAddress(surface) as *const u8,
            IOSurfaceGetAllocSize(surface)
        );

        let bytes_per_row = IOSurfaceGetBytesPerRow(surface);

        Frame { surface, inner, bytes_per_row }
    }

    /// MESHHARBOR PATCH: bytes between the starts of two consecutive rows.
    ///
    /// This is NOT derivable from the slice: `len()` is
    /// `IOSurfaceGetAllocSize`, the page-rounded total allocation, so
    /// `len() / height` overshoots the real pitch (and is usually not a
    /// multiple of the pixel size). Reading rows at that spacing shears the
    /// image progressively — which is what a consumer forced to guess ends up
    /// doing, because upstream exposes no accessor for the real value.
    pub fn bytes_per_row(&self) -> usize {
        self.bytes_per_row
    }
}

impl ops::Deref for Frame {
    type Target = [u8];
    fn deref<'a>(&'a self) -> &'a [u8] {
        self.inner
    }
}

impl Drop for Frame {
    fn drop(&mut self) {
        unsafe {
            IOSurfaceUnlock(
                self.surface,
                SURFACE_LOCK_READ_ONLY,
                ptr::null_mut()
            );

            IOSurfaceDecrementUseCount(self.surface);
            CFRelease(self.surface);
        }
    }
}
