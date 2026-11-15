use crate::translation::block::build_block;
use crate::translation::cache::{CachedBlock, CodeCache};
use std::{fmt::Debug, io};

use super::block::{BasicBlock, BlockExit};
use mbdi_interfaces::{code_memory::WritableCode, isa::DecodedInstruction};

pub fn translate_block<W: WritableCode>(
    block: BasicBlock,
    original_bytes: &[u8],
    page_size: usize,
    initial_capacity: usize,
    mut allocate: impl FnMut(usize) -> io::Result<W>,
    mut relocate: impl FnMut(&[u8], u32, u64, u64) -> io::Result<Vec<u8>>,
) -> io::Result<(W::Executable, BlockExit)> {
    if page_size == 0 || initial_capacity == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "page size and initial capacity must be nonzero",
        ));
    }
    let mut capacity = initial_capacity;
    for attempt in 1..=2 {
        let memory = allocate(capacity)?;
        let bytes = relocate(
            original_bytes,
            block.bitness,
            block.start_address,
            memory.address(),
        )?;
        if bytes.len() <= capacity {
            return Ok((memory.publish(&bytes)?, block.exit));
        }
        if attempt == 1 {
            capacity = bytes
                .len()
                .div_ceil(page_size)
                .checked_mul(page_size)
                .ok_or_else(|| io::Error::other("code capacity overflow"))?;
        }
    }
    Err(io::Error::other(
        "relocated block does not fit after two attempts",
    ))
}

pub struct BlockSource<'a> {
    pub bytes: &'a [u8],
    pub bitness: u32,
    pub guest_ip: u64,
}

pub fn prepare_block<'cache, W, DecodeError>(
    cache: &'cache mut CodeCache<W::Executable>,
    source: BlockSource<'_>,
    page_size: usize,
    initial_capacity: usize,
    decode_one: impl FnMut(&[u8], u32, u64) -> Result<DecodedInstruction, DecodeError>,
    allocate: impl FnMut(usize) -> io::Result<W>,
    relocate: impl FnMut(&[u8], u32, u64, u64) -> io::Result<Vec<u8>>,
) -> io::Result<&'cache CachedBlock<W::Executable>>
where
    W: WritableCode,
    DecodeError: Debug,
{
    cache.get_or_translate(source.bitness, source.guest_ip, || {
        let block = build_block(source.bytes, source.bitness, source.guest_ip, decode_one)
            .map_err(|err| io::Error::other(format!("block construction failed: {err:?}")))?;

        let block_len: usize = block
            .instructions
            .iter()
            .map(|instruction| usize::from(instruction.length))
            .sum();

        translate_block(
            block,
            &source.bytes[..block_len],
            page_size,
            initial_capacity,
            allocate,
            relocate,
        )
    })
}