#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn is_x86() -> bool {
    true
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn is_x86() -> bool {
    false
}
