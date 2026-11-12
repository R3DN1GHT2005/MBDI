use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, IcedError, IntelFormatter, Mnemonic, OpKind,
};
use mbdi_interfaces::isa::{ControlFlow, DecodedInstruction};

pub fn decode(bytes: &[u8], bitness: u32, rip: u64) -> Result<Vec<(u64, String)>, IcedError> {
    let mut decoder = Decoder::try_with_ip(bitness, bytes, rip, DecoderOptions::NONE)?;
    let mut formatter = IntelFormatter::new();
    let mut lines = Vec::new();
    for instruction in decoder.iter() {
        if instruction.is_invalid() {
            break;
        }
        let mut assembly = String::new();
        formatter.format(&instruction, &mut assembly);
        lines.push((instruction.ip(), assembly));
    }
    Ok(lines)
}

#[derive(Debug)]
pub enum DecodeError {
    Setup(IcedError),
    InvalidInstruction,
}

pub fn decode_one(
    bytes: &[u8],
    bitness: u32,
    address: u64,
) -> Result<DecodedInstruction, DecodeError> {
    let mut decoder = Decoder::try_with_ip(bitness, bytes, address, DecoderOptions::NONE)
        .map_err(DecodeError::Setup)?;
    let instruction = decoder.decode();
    if instruction.is_invalid() {
        return Err(DecodeError::InvalidInstruction);
    }
    let near_target = matches!(
        instruction.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    );
    let flow = match instruction.flow_control() {
        FlowControl::Next => ControlFlow::Sequential,
        FlowControl::ConditionalBranch => ControlFlow::ConditionalBranch,
        FlowControl::UnconditionalBranch if near_target => ControlFlow::DirectJump,
        FlowControl::IndirectBranch => ControlFlow::IndirectJump,
        FlowControl::Call if near_target => ControlFlow::DirectCall,
        FlowControl::IndirectCall => ControlFlow::IndirectCall,
        FlowControl::Return if instruction.mnemonic() == Mnemonic::Ret => ControlFlow::Return,
        _ => ControlFlow::Other,
    };

    let direct_target = if near_target
        && matches!(
            flow,
            ControlFlow::ConditionalBranch | ControlFlow::DirectJump | ControlFlow::DirectCall
        ) {
        Some(instruction.near_branch_target())
    } else {
        None
    };

    Ok(DecodedInstruction {
        address: instruction.ip(),
        length: instruction.len() as u8,
        next_address: instruction.next_ip(),
        direct_target,
        flow,
    })
}
