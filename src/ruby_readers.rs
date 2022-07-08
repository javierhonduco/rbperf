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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ruby_stack_status_STACK_INCOMPLETE, COMM_MAXLEN, MAX_STACK};

    #[test]
    fn test_parse_empty_char_buffer() {
        let buffer: [u8; 20] = [0; 20];
        assert!(unsafe { str_from_u8_nul(&buffer) }.is_ok());
        assert_eq!("", unsafe { str_from_u8_nul(&buffer) }.unwrap());
    }

    #[test]
    fn test_parse_char_buffer_works() {
        let mut buffer: [u8; 20] = [0; 20];
        buffer[0] = 114; // r
        buffer[1] = 117; // u
        buffer[2] = 98; // b
        buffer[3] = 121; // y

        assert!(unsafe { str_from_u8_nul(&buffer) }.is_ok());
        assert_eq!("ruby", unsafe { str_from_u8_nul(&buffer) }.unwrap());
    }

    #[test]
    fn test_parse_malformed_char_buffer_errors() {
        let mut buffer: [u8; 20] = [0; 20];
        buffer[0] = 0x80;

        assert!(unsafe { str_from_u8_nul(&buffer) }.is_err());
    }

    #[test]
    fn test_parse_stack() {
        let mut stack: [u32; MAX_STACK as usize] = [0; MAX_STACK as usize];
        stack[0] = 1;
        stack[1] = 2;

        let mut test_comm: [i8; COMM_MAXLEN as usize] = [0; COMM_MAXLEN as usize];
        test_comm[0] = 1;
        test_comm[1] = 2;
        test_comm[2] = 3;
        test_comm[3] = 4;

        let ruby_stack = RubyStack {
            timestamp: 101,
            frames: stack,
            pid: 5,
            cpu: 1,
            size: 2,
            expected_size: 2,
            comm: test_comm,
            stack_status: ruby_stack_status_STACK_INCOMPLETE,
        };

        let ruby_stack_bytes = unsafe { any_as_u8_slice(&ruby_stack) };

        assert_eq!(ruby_stack, unsafe { parse_stack(ruby_stack_bytes) });
    }
}
