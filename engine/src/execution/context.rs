use super::dispatcher::{BlockOutcome, GuestLocation};
use crate::translation::block::BlockExit;
use std::io;

#[derive(Debug, Default)]
pub struct X64EaxContext {
    pub eax: u32,
}

pub fn execute_eax_block(
    context: &mut X64EaxContext,
    location: GuestLocation,
    exit: &BlockExit,
    invoke: impl FnOnce(u32) -> io::Result<u32>,
) -> io::Result<BlockOutcome> {
    if location.bitness != 64 {
        return Err(io::Error::other("Eax executor requires x64 mode"));
    }
    let next = match exit {
        BlockExit::DirectJump { target } => Some(GuestLocation {
            guest_ip: *target,
            bitness: location.bitness,
        }),
        BlockExit::Return => None,
        _ => return Err(io::Error::other("unsupported block exit!")),
    };
    context.eax = invoke(context.eax)?;
    Ok(match next {
        Some(location) => BlockOutcome::Continue(location),
        None => BlockOutcome::Finished(context.eax),
    })
}
