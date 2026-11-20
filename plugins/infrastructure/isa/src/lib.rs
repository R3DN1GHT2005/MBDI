mod decoder;
mod encoder;

pub use decoder::{DecodeError, decode, decode_one};
pub use encoder::{RelocateError, emit_jcc_exit_x64, relocate_block};
