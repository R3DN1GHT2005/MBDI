use mbdi_interfaces::isa::{ControlFlow, DecodedInstruction};

#[derive(Debug)]
pub enum BlockError<E> {
    Decode(E),
    InvalidLength,
    UnsupportedFlow,
    MissingTerminator,
    MissingDirectTarget,
}

pub struct BasicBlock {
    pub start_address: u64,
    pub bitness: u32,
    pub instructions: Vec<DecodedInstruction>,
    pub exit: BlockExit,
}

pub fn build_block<E>(
    mut bytes: &[u8],
    bitness: u32,
    mut address: u64,
    mut decode_one: impl FnMut(&[u8], u32, u64) -> Result<DecodedInstruction, E>,
) -> Result<BasicBlock, BlockError<E>> {
    let start_address = address;
    let mut instructions = Vec::new();

    while !bytes.is_empty() {
        let instruction = decode_one(bytes, bitness, address).map_err(BlockError::Decode)?;
        let length = usize::from(instruction.length);

        if length == 0 || length > 15 || length > bytes.len() {
            return Err(BlockError::InvalidLength);
        }

        let exit = match instruction.flow {
            ControlFlow::Sequential => None,
            ControlFlow::ConditionalBranch => Some(BlockExit::Conditional {
                taken: instruction
                    .direct_target
                    .ok_or(BlockError::MissingDirectTarget)?,
                not_taken: instruction.next_address,
            }),
            ControlFlow::DirectJump => Some(BlockExit::DirectJump {
                target: instruction
                    .direct_target
                    .ok_or(BlockError::MissingDirectTarget)?,
            }),
            ControlFlow::DirectFarJump { selector, offset } => {
                Some(BlockExit::DirectFarJump { selector, offset })
            }
            ControlFlow::IndirectJump => Some(BlockExit::IndirectJump),
            ControlFlow::DirectCall => Some(BlockExit::DirectCall {
                target: instruction
                    .direct_target
                    .ok_or(BlockError::MissingDirectTarget)?,
                return_address: instruction.next_address,
            }),
            ControlFlow::IndirectCall => Some(BlockExit::IndirectCall {
                return_address: instruction.next_address,
            }),
            ControlFlow::Return => Some(BlockExit::Return),
            ControlFlow::FarReturn64 => Some(BlockExit::FarReturn64),
            ControlFlow::Other => return Err(BlockError::UnsupportedFlow),
        };

        bytes = &bytes[length..];
        address = instruction.next_address;
        instructions.push(instruction);

        if let Some(exit) = exit {
            return Ok(BasicBlock {
                start_address,
                bitness,
                instructions,
                exit,
            });
        }
    }

    Err(BlockError::MissingTerminator)
}

#[derive(Debug)]
pub enum BlockExit {
    Conditional { taken: u64, not_taken: u64 },
    DirectJump { target: u64 },
    IndirectJump,
    DirectCall { target: u64, return_address: u64 },
    DirectFarJump { selector: u16, offset: u32 },
    IndirectCall { return_address: u64 },
    FarReturn64,
    Return,
}
