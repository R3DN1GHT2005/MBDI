use std::io;

use isa::{
    decode_one, emit_jcc_exit_x64, encode_indirect_call_target_x64,
    encode_indirect_jump_target_x64, relocate_block,
};
use mbdi_arch_runtime::x64_gate::{X64Gate, X64GuestState};
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

struct WindowsX64Runtime {
    gate: X64Gate,
    stop_ip: u64,
    remaining_blocks: usize,
}

impl CachedBlockRuntime<ExecutableCode> for WindowsX64Runtime {
    fn encode_block(
        &self,
        block: &BasicBlock,
        source: &[u8],
        cache_ip: u64,
    ) -> io::Result<Vec<u8>> {
        let (entry, _) = self.gate.cache_shims();

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
                match site.exit {
                    BlockExit::DirectJump { target } => {
                        code.extend_from_slice(&self.gate.exit_to(*target));
                    }
                    BlockExit::Conditional { taken, not_taken } => {
                        let fallthrough_exit = self.gate.exit_to(*not_taken);
                        let taken_exit = self.gate.exit_to(*taken);

                        emit_jcc_exit_x64(
                            site.original_bytes,
                            site.guest_ip,
                            site.cache_ip,
                            &fallthrough_exit,
                            &taken_exit,
                            code,
                        )?;
                    }
                    BlockExit::DirectCall {
                        target,
                        return_address,
                    } => {
                        code.extend_from_slice(&self.gate.call_to(*target, *return_address));
                    }
                    BlockExit::IndirectCall { return_address } => {
                        let load =
                            encode_indirect_call_target_x64(site.original_bytes, site.guest_ip)?;
                        self.gate.emit_indirect_call(&load, *return_address, code);
                    }
                    BlockExit::IndirectJump => {
                        let load =
                            encode_indirect_jump_target_x64(site.original_bytes, site.guest_ip)?;
                        self.gate.emit_indirect_jump(&load, code);
                    }
                    BlockExit::Return if site.original_bytes == b"\xC3" => {
                        code.extend_from_slice(&self.gate.return_to_guest());
                    }
                    _ => {
                        return Err(io::Error::other(format!(
                            "unsupported x64 block exit at {:#x}",
                            site.guest_ip,
                        )));
                    }
                }

                Ok(())
            },
        )
    }

    fn run_block(
        &mut self,
        location: GuestLocation,
        block: &CachedBlock<ExecutableCode>,
    ) -> io::Result<BlockOutcome> {
        if self.remaining_blocks == 0 {
            return Err(io::Error::other(format!(
                "block budget exhausted at {:#x}",
                location.guest_ip,
            )));
        }
        self.remaining_blocks -= 1;

        // SAFETY: run_x64_region owns this runtime and its matching cache.
        // Its caller supplies guest code and memory valid for this gate.
        unsafe { self.gate.run(block.code.address()) };

        let next_ip = self.gate.next_guest_ip();
        if next_ip == self.stop_ip {
            // The result is read from the full guest RAX by run_x64_region.
            return Ok(BlockOutcome::Finished(0));
        }

        Ok(BlockOutcome::Continue(GuestLocation {
            guest_ip: next_ip,
            bitness: location.bitness,
        }))
    }
}

/// Executes a controlled x64 region and returns the full guest RAX.
///
/// # Safety
/// The caller must keep the guest stack and all memory used by the guest
/// valid throughout the run. The guest must use the supported integer
/// profile and reach the generated exits without faults, unwinding,
/// reentrancy, or unmediated control transfers.
pub unsafe fn run_x64_region(
    region: &CodeRegion<'_>,
    guest: X64GuestState,
    stop_ip: u64,
    max_blocks: usize,
) -> io::Result<u64> {
    if region.bitness != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows x64 execution requires a 64-bit region",
        ));
    }

    if region.start_address == stop_ip {
        return Ok(guest.rax);
    }

    let mut runtime = WindowsX64Runtime {
        gate: X64Gate::new(guest),
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
    )?;

    Ok(runtime.gate.guest().rax)
}
