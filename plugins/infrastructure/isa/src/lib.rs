mod decoder;
mod encoder;

pub use decoder::{DecodeError, decode, decode_one};
pub use encoder::{
    RelocateError, emit_jcc_exit_x64, encode_indirect_call_target_x64,
    encode_indirect_jump_target_x64, relocate_block,
};
