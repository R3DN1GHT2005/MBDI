#[cfg(windows)]
pub mod executable;

#[cfg(all(windows, target_arch = "x86_64"))]
pub mod x64_gate;
