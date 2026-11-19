#![cfg(all(windows, target_arch = "x86_64"))]

use std::io;

use isa::{decode_one, relocate_block};
use mbdi_engine::{
    execution::dispatcher::{BlockOutcome, GuestLocation, dispatch_region},
    translation::{block::BlockExit, cache::CodeCache, source::CodeRegion},
};
use platform_windows::executable::{CodeMemory, ExecutableCode, page_size};

#[test]
fn prepares_and_executes_the_terminal_blocks() {
    const ENTRY: u64 = 0x1000;
    const NOT_TAKEN: u64 = 0x1002;
    const TAKEN: u64 = 0x1008;

    let original = [
        0x75, 0x06, // 0x1000: jne 0x1008
        0xB8, 7, 0, 0, 0, 0xC3, // 0x1002: mov eax, 7; ret
        0xB8, 42, 0, 0, 0, 0xC3, // 0x1008: mov eax, 42; ret
    ];

    let region = CodeRegion {
        start_address: ENTRY,
        bitness: 64,
        bytes: &original,
    };

    let mut cache = CodeCache::<ExecutableCode>::default();
    let page_bytes = page_size();

    for (take_branch, target, expected) in [(false, NOT_TAKEN, 7), (true, TAKEN, 42)] {
        let mut visited = Vec::new();

        let result = dispatch_region(
            &region,
            &mut cache,
            page_bytes,
            decode_one,
            CodeMemory::allocate,
            |bytes, bitness, source, destination| {
                relocate_block(bytes, bitness, source, destination)
                    .map_err(|error| io::Error::other(format!("relocation failed: {error:?}")))
            },
            |location, block| {
                visited.push(location.guest_ip);

                match &block.exit {
                    BlockExit::Conditional { taken, not_taken } => {
                        let guest_ip = if take_branch { *taken } else { *not_taken };

                        Ok(BlockOutcome::Continue(GuestLocation {
                            guest_ip,
                            bitness: location.bitness,
                        }))
                    }
                    BlockExit::Return if matches!(location.guest_ip, NOT_TAKEN | TAKEN) => {
                        // SAFETY: These two fixture blocks are `mov eax, imm32; ret`.
                        // They match this signature, and the cache owns their memory.
                        let value = unsafe {
                            let run: unsafe extern "C" fn() -> u32 =
                                std::mem::transmute(block.code.address() as usize);
                            run()
                        };

                        Ok(BlockOutcome::Finished(value))
                    }
                    _ => Err(io::Error::other("unexpected block exit")),
                }
            },
        )
        .expect("dispatch failed");

        assert_eq!(visited, [ENTRY, target]);
        assert_eq!(result, expected);
    }
}
