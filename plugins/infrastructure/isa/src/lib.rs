mod decoder;
mod encoder;

pub use decoder::{DecodeError, decode, decode_one};
pub use encoder::{RelocateError, relocate_block};
