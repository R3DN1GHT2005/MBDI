#[cfg(all(windows, target_arch = "x86_64"))]
pub mod windows_x64;

#[cfg(all(windows, target_arch = "x86"))]
pub mod windows_x86;
