use std::io;

use isa::{decode_one, relocate_block};
use mbdi_arch_runtime::x86_gate::{X86Gate, X86GuestState};
use mbdi_engine::{
    execution::dispatcher::{
        BlockOutcome, CachedBlockRuntime, GuestLocation, dispatch_cached_region,
    },
    translation::{
        block::{BasicBlock, BlockExit},
        cache::{CachedBlock, CodeCache},
        encode::encode_dispatch_block,
        source::CodeRegion,
    },
};
use platform_windows::executable::{CodeMemory, ExecutableCode, page_size};

struct WindowsX86Runtime {
    gate: X86Gate,
    stop_ip: u64,
    remaining_blocks: usize,
}

impl CachedBlockRuntime<ExecutableCode> for WindowsX86Runtime {
    fn encode_block(
        &self,
        block: &BasicBlock,
        source: &[u8],
        cache_ip: u64,
    ) -> io::Result<Vec<u8>> {
        let (entry, leave) = self.gate.cache_shims();

        encode_dispatch_block(
            block,
            source,
            cache_ip,
            &entry,
            |body, bitness, source_ip, body_ip| {
                relocate_block(body, bitness, source_ip, body_ip)
                    .map_err(|error| io::Error::other(format!("relocation failed: {error:?}")))
            },
            |site, code| {
                if !matches!(site.exit, BlockExit::DirectJump { .. }) {
                    return Err(io::Error::other(format!(
                        "unsupported x86 block exit at {:#x}",
                        site.guest_ip,
                    )));
                }

                code.extend_from_slice(&leave);
                Ok(())
            },
        )
    }

    fn run_block(
        &mut self,
        location: GuestLocation,
        block: &CachedBlock<ExecutableCode>,
    ) -> io::Result<BlockOutcome> {
        let BlockExit::DirectJump { target } = &block.exit else {
            return Err(io::Error::other("expected a direct x86 jump"));
        };

        if self.remaining_blocks == 0 {
            return Err(io::Error::other(format!(
                "block budget exhausted at {:#x}",
                location.guest_ip,
            )));
        }
        self.remaining_blocks -= 1;

        // SAFETY: run_x86_region owns this gate and its matching cache.
        // Its caller supplies guest code and memory valid for the gate.
        unsafe { self.gate.run(block.code.address()) }?;

        if *target == self.stop_ip {
            return Ok(BlockOutcome::Finished(self.gate.guest().eax));
        }

        Ok(BlockOutcome::Continue(GuestLocation {
            guest_ip: *target,
            bitness: location.bitness,
        }))
    }
}

/// Executes a controlled x86 region and returns guest EAX.
///
/// # Safety
/// The caller must keep the guest stack and all memory used by the guest
/// valid throughout the run. Guest code must use the gate's supported
/// integer state and reach the generated exits without faults or unwind.
pub unsafe fn run_x86_region(
    region: &CodeRegion<'_>,
    guest: X86GuestState,
    stop_ip: u64,
    max_blocks: usize,
) -> io::Result<u32> {
    if region.bitness != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows x86 execution requires a 32-bit region",
        ));
    }

    if region.start_address == stop_ip {
        return Ok(guest.eax);
    }

    let mut runtime = WindowsX86Runtime {
        gate: X86Gate::new(guest),
        stop_ip,
        remaining_blocks: max_blocks,
    };
    let mut cache = CodeCache::<ExecutableCode>::default();

    dispatch_cached_region(
        region,
        &mut cache,
        page_size(),
        decode_one,
        CodeMemory::allocate,
        &mut runtime,
    )
}
