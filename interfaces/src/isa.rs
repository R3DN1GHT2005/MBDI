#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlFlow {
    Sequential,
    ConditionalBranch,
    DirectJump,
    IndirectJump,
    DirectCall,
    IndirectCall,
    Return,
    Other,
}

pub struct DecodedInstruction {
    pub address: u64,
    pub length: u8,
    pub next_address: u64,
    pub direct_target: Option<u64>,
    pub flow: ControlFlow,
}
