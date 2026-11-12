use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Decoder, DecoderOptions, IcedError, InstructionBlock,
};

#[derive(Debug)]
pub enum RelocateError {
    EmptyBlock,
    InvalidInstruction { address: u64 },
    Iced(IcedError),
}

pub fn relocate_block(
    bytes: &[u8],
    bitness: u32,
    source_ip: u64,
    destination_ip: u64,
) -> Result<Vec<u8>, RelocateError> {
    if bytes.is_empty() {
        return Err(RelocateError::EmptyBlock);
    }
    let mut decoder = Decoder::try_with_ip(bitness, bytes, source_ip, DecoderOptions::NONE)
        .map_err(RelocateError::Iced)?;
    let mut instructions = Vec::new();
    for instruction in decoder.iter() {
        if instruction.is_invalid() {
            return Err(RelocateError::InvalidInstruction {
                address: instruction.ip(),
            });
        }
        instructions.push(instruction);
    }
    let block = InstructionBlock::new(&instructions, destination_ip);
    let encoded = BlockEncoder::encode(bitness, block, BlockEncoderOptions::NONE)
        .map_err(RelocateError::Iced)?;
    Ok(encoded.code_buffer)
}
