use std::ptr;

use crate::{RubyFrame, RubyStack};

// from https://stackoverflow.com/questions/42066381/how-to-get-a-str-from-a-nul-terminated-byte-slice-if-the-nul-terminator-isnt
pub unsafe fn str_from_u8_nul_utf8_unchecked(utf8_src: &[u8]) -> &str {
    let nul_range_end = utf8_src
        .iter()
        .position(|&c| c == b'\0')
        .unwrap_or(utf8_src.len()); // default to length if no `\0` present
    ::std::str::from_utf8_unchecked(&utf8_src[0..nul_range_end])
}

// from https://stackoverflow.com/questions/28127165/how-to-convert-struct-to-u8
pub unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &mut [u8] {
    ::std::slice::from_raw_parts_mut((p as *const T) as *mut u8, ::std::mem::size_of::<T>())
}

pub unsafe fn parse_struct(x: &[u8]) -> RubyStack {
    ptr::read_unaligned(x.as_ptr() as *const RubyStack)
}

pub unsafe fn parse_frame(x: &[u8]) -> RubyFrame {
    ptr::read_unaligned(x.as_ptr() as *const RubyFrame)
}
