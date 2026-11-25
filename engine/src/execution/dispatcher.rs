use crate::translation::{
    block::BasicBlock,
    cache::{CachedBlock, CodeCache},
    source::{CodeRegion, CodeSource},
    translate::{BlockSource, prepare_block, prepare_block_with_encoder},
};
use mbdi_interfaces::{code_memory::WritableCode, isa::DecodedInstruction};
use std::{fmt::Debug, io};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestLocation {
    pub guest_ip: u64,
    pub bitness: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum BlockOutcome {
    Continue(GuestLocation),
    Finished(u32),
}

pub fn dispatch<E>(
    mut current: GuestLocation,
    mut run_block: impl FnMut(GuestLocation) -> Result<BlockOutcome, E>,
) -> Result<u32, E> {
    loop {
        match run_block(current)? {
            BlockOutcome::Continue(next) => current = next,
            BlockOutcome::Finished(value) => return Ok(value),
        }
    }
}

pub fn dispatch_region<W, DecodeError>(
    source: &impl CodeSource,
    cache: &mut CodeCache<W::Executable>,
    page_size: usize,
    mut decode_one: impl FnMut(&[u8], u32, u64) -> Result<DecodedInstruction, DecodeError>,
    mut allocate: impl FnMut(usize) -> io::Result<W>,
    mut relocate: impl FnMut(&[u8], u32, u64, u64) -> io::Result<Vec<u8>>,
    mut execute: impl FnMut(GuestLocation, &CachedBlock<W::Executable>) -> io::Result<BlockOutcome>,
) -> io::Result<u32>
where
    W: WritableCode,
    DecodeError: Debug,
{
    dispatch(source.entry(), |location| {
        let bytes = source.bytes_at(location).map_err(|error| {
            io::Error::other(format!("code fetch at {:#x}: {error:?}", location.guest_ip))
        })?;

        let block = prepare_block(
            cache,
            BlockSource {
                bytes,
                bitness: location.bitness,
                guest_ip: location.guest_ip,
            },
            page_size,
            page_size,
            &mut decode_one,
            &mut allocate,
            &mut relocate,
        )?;

        execute(location, block)
    })
}

pub trait CachedBlockRuntime<C> {
    fn encode_block(&self, block: &BasicBlock, source: &[u8], cache_ip: u64)
    -> io::Result<Vec<u8>>;
    fn run_block(
        &mut self,
        location: GuestLocation,
        block: &CachedBlock<C>,
    ) -> io::Result<BlockOutcome>;
}
pub fn dispatch_cached_region<W, DecodeError>(
    region: &CodeRegion<'_>,
    cache: &mut CodeCache<W::Executable>,
    page_size: usize,
    mut decode_one: impl FnMut(&[u8], u32, u64) -> Result<DecodedInstruction, DecodeError>,
    mut allocate: impl FnMut(usize) -> io::Result<W>,
    runtime: &mut impl CachedBlockRuntime<W::Executable>,
) -> io::Result<u32>
where
    W: WritableCode,
    DecodeError: Debug,
{
    let entry = GuestLocation {
        guest_ip: region.start_address,
        bitness: region.bitness,
    };

    dispatch(entry, |location| -> io::Result<BlockOutcome> {
        let source = region.bytes_at(location).map_err(|error| {
            io::Error::other(format!(
                "code fetch failed at {:#x}: {error:?}",
                location.guest_ip,
            ))
        })?;

        let block = prepare_block_with_encoder(
            cache,
            BlockSource {
                bytes: source,
                bitness: location.bitness,
                guest_ip: location.guest_ip,
            },
            page_size,
            page_size,
            &mut decode_one,
            &mut allocate,
            |block, bytes, cache_ip| runtime.encode_block(block, bytes, cache_ip),
        )?;

        runtime.run_block(location, block)
    })
}
