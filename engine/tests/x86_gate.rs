#![cfg(all(windows, target_arch = "x86"))]

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

#[test]
fn runs_a_native_x86_block_on_the_guest_stack() -> io::Result<()> {
    const START: u64 = 0x1000;
    const STOP: u64 = START + 12;

    struct ProbeRuntime {
        gate: X86Gate,
    }

    impl CachedBlockRuntime<ExecutableCode> for ProbeRuntime {
        fn encode_block(
            &self,
            block: &BasicBlock,
            source: &[u8],
            cache_ip: u64,
        ) -> io::Result<Vec<u8>> {
            let (entry, leave) = self.gate.cache_shims();

            let encoded = encode_dispatch_block(
                block,
                source,
                cache_ip,
                &entry,
                |body, bitness, source_ip, body_ip| {
                    relocate_block(body, bitness, source_ip, body_ip)
                        .map_err(|error| io::Error::other(format!("relocation failed: {error:?}")))
                },
                |site, code| match site.exit {
                    BlockExit::DirectJump { target } if *target == STOP => {
                        code.extend_from_slice(&leave);
                        Ok(())
                    }
                    _ => Err(io::Error::other(
                        "expected a direct jump to the stop address",
                    )),
                },
            )?;

            eprintln!("[x86] cache bytes at {cache_ip:#010x}: {encoded:02X?}");
            Ok(encoded)
        }

        fn run_block(
            &mut self,
            _location: GuestLocation,
            block: &CachedBlock<ExecutableCode>,
        ) -> io::Result<BlockOutcome> {
            // SAFETY: The fixture owns the guest stack and executes only the
            // known integer block with this gate's matching shims.
            unsafe { self.gate.run(block.code.address()) }?;

            Ok(BlockOutcome::Finished(self.gate.guest().eax))
        }
    }

    let bytes = [
        0xB8, 40, 0, 0, 0,    // mov eax, 40
        0x50, // push eax
        0x5A, // pop edx
        0x83, 0xC0, 2, // add eax, 2
        0xEB, 0, // jmp STOP
    ];

    let region = CodeRegion {
        start_address: START,
        bitness: 32,
        bytes: &bytes,
    };

    let mut stack = Box::new([0_u32; 512]);
    let stack_top = stack.as_mut_ptr().wrapping_add(stack.len()) as u32;

    let mut runtime = ProbeRuntime {
        gate: X86Gate::new(X86GuestState {
            esp: stack_top,
            ..X86GuestState::default()
        }),
    };
    let mut cache = CodeCache::<ExecutableCode>::default();

    let result = dispatch_cached_region(
        &region,
        &mut cache,
        page_size(),
        decode_one,
        CodeMemory::allocate,
        &mut runtime,
    )?;

    let guest = runtime.gate.guest();
    assert_eq!(result, 42);
    assert_eq!(guest.eax, 42);
    assert_eq!(guest.edx, 40);
    assert_eq!(guest.esp, stack_top);
    assert_eq!(stack[511], 40);

    Ok(())
}
