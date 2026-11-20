use std::io;

use super::block::{BasicBlock, BlockExit};

pub struct ExitSite<'a> {
    pub exit: &'a BlockExit,
    pub original_bytes: &'a [u8],
    pub guest_ip: u64,
    pub cache_ip: u64,
    pub bitness: u32,
}

pub fn encode_dispatch_block(
    block: &BasicBlock,
    source: &[u8],
    cache_ip: u64,
    entry: &[u8],
    relocate: impl FnOnce(&[u8], u32, u64, u64) -> io::Result<Vec<u8>>,
    emit_exit: impl FnOnce(ExitSite<'_>, &mut Vec<u8>) -> io::Result<()>,
) -> io::Result<Vec<u8>> {
    let terminator = block
        .instructions
        .last()
        .ok_or_else(|| io::Error::other("block has no instructions"))?;

    let body_len = terminator
        .address
        .checked_sub(block.start_address)
        .and_then(|offset| usize::try_from(offset).ok())
        .ok_or_else(|| io::Error::other("invalid terminator address"))?;

    let block_len = body_len
        .checked_add(usize::from(terminator.length))
        .ok_or_else(|| io::Error::other("block length overflow"))?;

    let block_bytes = source
        .get(..block_len)
        .ok_or_else(|| io::Error::other("truncated source block"))?;

    let (body, original_exit) = block_bytes.split_at(body_len);
    let mut code = entry.to_vec();

    if !body.is_empty() {
        let body_ip = cache_ip
            .checked_add(code.len() as u64)
            .ok_or_else(|| io::Error::other("cache body address overflow"))?;

        let relocated_body = relocate(body, block.bitness, block.start_address, body_ip)?;
        code.extend(relocated_body);
    }

    let exit_cache_ip = cache_ip
        .checked_add(code.len() as u64)
        .ok_or_else(|| io::Error::other("cache exit address overflow"))?;

    emit_exit(
        ExitSite {
            exit: &block.exit,
            original_bytes: original_exit,
            guest_ip: terminator.address,
            cache_ip: exit_cache_ip,
            bitness: block.bitness,
        },
        &mut code,
    )?;

    Ok(code)
}
