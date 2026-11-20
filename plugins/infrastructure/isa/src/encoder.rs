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

pub fn emit_jcc_exit_x64(
    original: &[u8],
    guest_ip: u64,
    cache_ip: u64,
    fallthrough: &[u8],
    taken: &[u8],
    code: &mut Vec<u8>,
) -> std::io::Result<()> {
    use std::io;

    use iced_x86::{Decoder, DecoderOptions, Encoder, Instruction, OpKind};

    const NEAR_JCC_LEN: usize = 6;

    let mut decoder = Decoder::with_ip(64, original, guest_ip, DecoderOptions::NONE);
    let mut branch = decoder.decode();

    if branch.is_invalid()
        || decoder.can_decode()
        || !branch.is_jcc_short_or_near()
        || branch.op0_kind() != OpKind::NearBranch64
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected a single x64 Jcc instruction",
        ));
    }

    let taken_ip = cache_ip
        .checked_add(NEAR_JCC_LEN as u64)
        .and_then(|ip| ip.checked_add(fallthrough.len() as u64))
        .ok_or_else(|| io::Error::other("conditional exit address overflow"))?;

    branch.as_near_branch();
    let local_branch =
        Instruction::with_branch(branch.code(), taken_ip).map_err(io::Error::other)?;

    let mut encoder = Encoder::new(64);
    let length = encoder
        .encode(&local_branch, cache_ip)
        .map_err(io::Error::other)?;

    if length != NEAR_JCC_LEN {
        return Err(io::Error::other("unexpected x64 near Jcc length"));
    }

    code.extend(encoder.take_buffer());
    code.extend_from_slice(fallthrough);
    code.extend_from_slice(taken);

    Ok(())
}
