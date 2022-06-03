use std::ptr;
use std::str::Utf8Error;

use crate::{RubyFrame, RubyStack};

pub unsafe fn str_from_u8_nul(utf8_src: &[u8]) -> Result<&str, Utf8Error> {
    let nul_range_end = utf8_src
        .iter()
        .position(|&c| c == b'\0')
        .unwrap_or(utf8_src.len()); // default to length if no `\0` present
    ::std::str::from_utf8(&utf8_src[0..nul_range_end])
}

pub unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::std::slice::from_raw_parts((p as *const T) as *const u8, ::std::mem::size_of::<T>())
}

pub unsafe fn parse_stack(x: &[u8]) -> RubyStack {
    ptr::read_unaligned(x.as_ptr() as *const RubyStack)
}

pub unsafe fn parse_frame(x: &[u8]) -> RubyFrame {
    ptr::read_unaligned(x.as_ptr() as *const RubyFrame)
}
