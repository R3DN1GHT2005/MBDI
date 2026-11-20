use super::block::{BasicBlock, BlockExit, build_block};
use super::cache::{CachedBlock, CodeCache};
use mbdi_interfaces::{code_memory::WritableCode, isa::DecodedInstruction};
use std::{fmt::Debug, io};

pub struct BlockSource<'a> {
    pub bytes: &'a [u8],
    pub bitness: u32,
    pub guest_ip: u64,
}

pub fn translate_block<W: WritableCode>(
    block: BasicBlock,
    original_bytes: &[u8],
    page_size: usize,
    initial_capacity: usize,
    allocate: impl FnMut(usize) -> io::Result<W>,
    mut relocate: impl FnMut(&[u8], u32, u64, u64) -> io::Result<Vec<u8>>,
) -> io::Result<(W::Executable, BlockExit)> {
    translate_block_with_encoder(
        block,
        original_bytes,
        page_size,
        initial_capacity,
        allocate,
        |block, bytes, destination| {
            relocate(bytes, block.bitness, block.start_address, destination)
        },
    )
}

fn translate_block_with_encoder<W: WritableCode>(
    block: BasicBlock,
    original_bytes: &[u8],
    page_size: usize,
    initial_capacity: usize,
    mut allocate: impl FnMut(usize) -> io::Result<W>,
    mut encode: impl FnMut(&BasicBlock, &[u8], u64) -> io::Result<Vec<u8>>,
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
        let bytes = encode(&block, original_bytes, memory.address())?;

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
        "encoded block does not fit after two attempts",
    ))
}

pub fn prepare_block<'cache, W, DecodeError>(
    cache: &'cache mut CodeCache<W::Executable>,
    source: BlockSource<'_>,
    page_size: usize,
    initial_capacity: usize,
    decode_one: impl FnMut(&[u8], u32, u64) -> Result<DecodedInstruction, DecodeError>,
    allocate: impl FnMut(usize) -> io::Result<W>,
    mut relocate: impl FnMut(&[u8], u32, u64, u64) -> io::Result<Vec<u8>>,
) -> io::Result<&'cache CachedBlock<W::Executable>>
where
    W: WritableCode,
    DecodeError: Debug,
{
    prepare_block_with_encoder(
        cache,
        source,
        page_size,
        initial_capacity,
        decode_one,
        allocate,
        |block, bytes, destination| {
            relocate(bytes, block.bitness, block.start_address, destination)
        },
    )
}

pub fn prepare_block_with_encoder<'cache, W, DecodeError>(
    cache: &'cache mut CodeCache<W::Executable>,
    source: BlockSource<'_>,
    page_size: usize,
    initial_capacity: usize,
    decode_one: impl FnMut(&[u8], u32, u64) -> Result<DecodedInstruction, DecodeError>,
    allocate: impl FnMut(usize) -> io::Result<W>,
    encode: impl FnMut(&BasicBlock, &[u8], u64) -> io::Result<Vec<u8>>,
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

        translate_block_with_encoder(
            block,
            &source.bytes[..block_len],
            page_size,
            initial_capacity,
            allocate,
            encode,
        )
    })
}
