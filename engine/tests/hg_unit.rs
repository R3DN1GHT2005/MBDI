#[test]
fn dispatch_keeps_x86_and_x64_blocks_separate_at_the_same_address() -> std::io::Result<()> {
    use std::{cell::Cell, io};

    use isa::decode_one;
    use mbdi_engine::{
        execution::dispatcher::{
            BlockOutcome, CachedBlockRuntime, FlatCodeSegment, GuestLocation,
            dispatch_cached_region, resolve_flat_far_jump, resolve_flat_far_return64_to_x86,
        },
        translation::{
            block::{BasicBlock, BlockExit},
            cache::{CachedBlock, CodeCache},
            source::{CodeImage, CodeRegion},
        },
    };
    use mbdi_interfaces::code_memory::WritableCode;

    const IP: u64 = 0x1000;
    const X64_SELECTOR: u16 = 0x1234;
    const X86_SELECTOR: u16 = 0x2344;

    const SEGMENTS: [FlatCodeSegment; 2] = [
        FlatCodeSegment {
            selector: X64_SELECTOR,
            bitness: 64,
        },
        FlatCodeSegment {
            selector: X86_SELECTOR,
            bitness: 32,
        },
    ];

    struct TestMemory;

    impl WritableCode for TestMemory {
        type Executable = Vec<u8>;

        fn address(&self) -> u64 {
            0x8000
        }

        fn publish(self, bytes: &[u8]) -> io::Result<Self::Executable> {
            Ok(bytes.to_vec())
        }
    }

    #[derive(Default)]
    struct TestRuntime {
        translations: Cell<usize>,
        visits: Vec<(u32, u8)>,
        active_bitness: u32,
        switches: Vec<(u32, u32)>,
        return_stack: [u8; 16],
        stack_cursor: usize,
    }

    impl CachedBlockRuntime<Vec<u8>> for TestRuntime {
        fn encode_block(
            &self,
            _block: &BasicBlock,
            bytes: &[u8],
            _cache_ip: u64,
        ) -> io::Result<Vec<u8>> {
            self.translations.set(self.translations.get() + 1);
            Ok(bytes.to_vec())
        }

        fn switch_guest_mode(&mut self, from: GuestLocation, to: GuestLocation) -> io::Result<()> {
            assert_eq!(self.active_bitness, from.bitness);
            self.switches.push((from.bitness, to.bitness));
            self.active_bitness = to.bitness;
            Ok(())
        }

        fn run_block(
            &mut self,
            location: GuestLocation,
            block: &CachedBlock<Vec<u8>>,
        ) -> io::Result<BlockOutcome> {
            assert_eq!(location.bitness, self.active_bitness);
            self.visits.push((location.bitness, block.code[1]));

            match (self.visits.len(), &block.exit) {
                (1, BlockExit::DirectFarJump { selector, offset }) => {
                    let next = resolve_flat_far_jump(*selector, *offset, &SEGMENTS)?;
                    Ok(BlockOutcome::Continue(next))
                }
                (2, BlockExit::FarReturn64) => {
                    let (next, consumed) = resolve_flat_far_return64_to_x86(
                        &self.return_stack[self.stack_cursor..],
                        &SEGMENTS,
                    )?;
                    self.stack_cursor += consumed;
                    Ok(BlockOutcome::Continue(next))
                }
                (3, BlockExit::DirectFarJump { .. }) => Ok(BlockOutcome::Finished(0)),
                _ => Err(io::Error::other("unexpected mixed-mode test exit")),
            }
        }
    }

    let x86 = [
        0xB8, 32, 0, 0, 0, // mov eax, 32
        0xEA, 0x00, 0x10, 0, 0, 0x34, 0x12, // jmp far 0x1234:0x1000
    ];
    let x64 = [
        0xB8, 64, 0, 0, 0, // mov eax, 64
        0x48, 0xCB, // retfq
    ];

    let regions = [
        CodeRegion {
            start_address: IP,
            bitness: 32,
            bytes: &x86,
        },
        CodeRegion {
            start_address: IP,
            bitness: 64,
            bytes: &x64,
        },
    ];
    let image = CodeImage {
        entry: GuestLocation {
            guest_ip: IP,
            bitness: 32,
        },
        regions: &regions,
    };

    let mut return_stack = [0; 16];
    return_stack[..8].copy_from_slice(&IP.to_le_bytes());
    return_stack[8..].copy_from_slice(&u64::from(X86_SELECTOR).to_le_bytes());

    let mut cache = CodeCache::default();
    let mut runtime = TestRuntime {
        active_bitness: 32,
        return_stack,
        ..TestRuntime::default()
    };

    dispatch_cached_region(
        &image,
        &mut cache,
        4096,
        decode_one,
        |_| Ok(TestMemory),
        &mut runtime,
    )?;

    assert_eq!(runtime.visits, [(32, 32), (64, 64), (32, 32)]);
    assert_eq!(runtime.translations.get(), 2);
    assert_eq!(runtime.switches, [(32, 64), (64, 32)]);
    assert_eq!(runtime.active_bitness, 32);
    assert_eq!(runtime.stack_cursor, 16);

    Ok(())
}

#[test]
fn preserves_the_selector_and_offset_of_a_direct_far_jump() -> std::io::Result<()> {
    use isa::decode_one;
    use mbdi_engine::translation::block::{BlockExit, build_block};

    let bytes = [
        0x90, // nop
        0xEA, 0, 0x20, 0, 0, 0x34, 0x12, // jmp far 0x1234:0x2000
        0x90, // byte beyond the block
    ];

    let block = build_block(&bytes, 32, 0x1000, decode_one)
        .map_err(|error| std::io::Error::other(format!("block construction failed: {error:?}")))?;

    assert_eq!(block.instructions.len(), 2);
    assert!(matches!(
        block.exit,
        BlockExit::DirectFarJump {
            selector: 0x1234,
            offset: 0x2000,
        }
    ));

    Ok(())
}
