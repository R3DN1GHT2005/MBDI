use crate::translation::{
    block::BasicBlock,
    cache::{CachedBlock, CodeCache},
    source::CodeSource,
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

    fn switch_guest_mode(&mut self, from: GuestLocation, to: GuestLocation) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "guest mode switch {} -> {} is unsupported (target {:#x}",
                from.bitness, to.bitness, to.guest_ip
            ),
        ))
    }
}
pub fn dispatch_cached_region<W, DecodeError>(
    source: &impl CodeSource,
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
    dispatch(source.entry(), |location| -> io::Result<BlockOutcome> {
        let bytes = source.bytes_at(location).map_err(|error| {
            io::Error::other(format!(
                "code fetch failed at {:#x} in {}-bit mode: {error:?}",
                location.guest_ip, location.bitness,
            ))
        })?;

        let block = prepare_block_with_encoder(
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
            |block, bytes, cache_ip| runtime.encode_block(block, bytes, cache_ip),
        )?;

        let outcome = runtime.run_block(location, block)?;

        if let BlockOutcome::Continue(next) = &outcome
            && next.bitness != location.bitness
        {
            if !matches!((location.bitness, next.bitness), (32, 64) | (64, 32)) {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("unsupported guest mode: {}", next.bitness),
                ));
            }

            runtime.switch_guest_mode(location, *next)?;
        }

        Ok(outcome)
    })
}

pub struct FlatCodeSegment {
    pub selector: u16,
    pub bitness: u32,
}

pub fn resolve_flat_far_jump(
    selector: u16,
    offset: u32,
    segments: &[FlatCodeSegment],
) -> io::Result<GuestLocation> {
    let mut matching = segments
        .iter()
        .filter(|segment| segment.selector == selector);

    let segment = matching.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported far jump selector {selector:#06x}"),
        )
    })?;

    if matching.next().is_some() || !matches!(segment.bitness, 32 | 64) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid code segment configuration for {selector:#06x}"),
        ));
    }

    Ok(GuestLocation {
        guest_ip: u64::from(offset),
        bitness: segment.bitness,
    })
}

pub fn resolve_flat_far_return64_to_x86(
    stack_at_rsp: &[u8],
    segments: &[FlatCodeSegment],
) -> io::Result<(GuestLocation, usize)> {
    const FRAME_LEN: usize = 16;

    let frame = stack_at_rsp.first_chunk::<FRAME_LEN>().ok_or_else(|| {
        io::Error::new(io::ErrorKind::UnexpectedEof, "truncated far return frame")
    })?;

    let mut offset_bytes = [0; 8];
    offset_bytes.copy_from_slice(&frame[..8]);

    let offset = u32::try_from(u64::from_le_bytes(offset_bytes)).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "far return address exceeds x86 range",
        )
    })?;

    let selector = u16::from_le_bytes([frame[8], frame[9]]);
    let next = resolve_flat_far_jump(selector, offset, segments)?;

    if next.bitness != 32 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "expected an x86 target for the far return",
        ));
    }

    Ok((next, FRAME_LEN))
}
