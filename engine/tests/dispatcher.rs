#![cfg(all(windows, target_arch = "x86_64"))]

use std::io;

use isa::{decode_one, relocate_block};
use mbdi_arch_runtime::x64_gate::{X64Gate, X64GuestState};
use mbdi_engine::{
    execution::dispatcher::{BlockOutcome, GuestLocation, dispatch},
    translation::{
        block::BlockExit,
        encode::encode_dispatch_block,
        translate::{BlockSource, prepare_block_with_encoder},
    },
};
use mbdi_engine::{
    execution::{
        context::{X64EaxContext, execute_eax_block},
        dispatcher::dispatch_region,
    },
    translation::{cache::CodeCache, source::CodeRegion},
};
use platform_windows::executable::{CodeMemory, ExecutableCode, page_size};

#[test]
fn carries_guest_eax_between_cached_blocks() {
    const FIRST: u64 = 0x1000;
    const SECOND: u64 = 0x1007;

    let original = [
        0xB8, 5, 0, 0, 0, // 0x1000: mov eax, 5
        0xEB, 0x00, // 0x1005: jmp 0x1007
        0x83, 0xC0, 0x03, // 0x1007: add eax, 3
        0xC3, // 0x100a: ret
    ];

    let region = CodeRegion {
        start_address: FIRST,
        bitness: 64,
        bytes: &original,
    };

    let mut cache = CodeCache::<ExecutableCode>::default();
    let mut context = X64EaxContext::default();
    let mut visited = Vec::new();

    let result = dispatch_region(
        &region,
        &mut cache,
        page_size(),
        decode_one,
        CodeMemory::allocate,
        |bytes, _bitness, source, _destination| {
            // Emitem manual doar cele două blocuri cunoscute ale testului.
            // Metadata BlockExit vine în continuare din codul guest original.
            match (source, bytes) {
                (FIRST, [0xB8, 5, 0, 0, 0, 0xEB, 0x00]) => {
                    // mov eax, 5; ret
                    Ok(vec![0xB8, 5, 0, 0, 0, 0xC3])
                }
                (SECOND, [0x83, 0xC0, 0x03, 0xC3]) => {
                    // mov eax, ecx; add eax, 3; ret
                    Ok(vec![0x89, 0xC8, 0x83, 0xC0, 0x03, 0xC3])
                }
                _ => Err(io::Error::other("unexpected guest block")),
            }
        },
        |location, block| {
            visited.push((location.guest_ip, context.eax));

            // Aici se apelează funcția din engine.
            execute_eax_block(&mut context, location, &block.exit, |eax_in| {
                // SAFETY: The cache owns the executable allocation. The
                // emitter above only publishes the two known function bodies.
                let eax_out = unsafe {
                    let run: unsafe extern "C" fn(u32) -> u32 =
                        std::mem::transmute(block.code.address() as usize);
                    run(eax_in)
                };

                Ok(eax_out)
            })
        },
    )
    .expect("dispatch failed");

    assert_eq!(visited, [(FIRST, 0), (SECOND, 5)]);
    assert_eq!(result, 8);
    assert_eq!(context.eax, 8);
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn runs_a_guest_loop_with_a_native_jcc() -> std::io::Result<()> {
    use std::io;

    use isa::{decode_one, emit_jcc_exit_x64, relocate_block};
    use mbdi_arch_runtime::x64_gate::{X64Gate, X64GuestState};
    use mbdi_engine::{
        execution::dispatcher::{BlockOutcome, GuestLocation, dispatch},
        translation::{
            block::BlockExit,
            cache::CodeCache,
            encode::encode_dispatch_block,
            source::CodeRegion,
            translate::{BlockSource, prepare_block_with_encoder},
        },
    };
    use platform_windows::executable::{CodeMemory, ExecutableCode, page_size};

    const FIRST: u64 = 0x1000;
    const LOOP_HEAD: u64 = 0x1006;
    const STOP: u64 = 0x1013;

    let original = [
        0x48, 0x8D, 0x1C, 0x11, // 0x1000: lea rbx, [rcx + rdx]
        0xEB, 0x00, // 0x1004: jmp 0x1006
        0x48, 0x83, 0xEB, 0x01, // 0x1006: sub rbx, 1
        0x48, 0x89, 0xD8, // 0x100A: mov rax, rbx
        0x48, 0x83, 0xF8, 0x27, // 0x100D: cmp rax, 39
        0x75, 0xF3, // 0x1011: jne 0x1006
    ];

    let region = CodeRegion {
        start_address: FIRST,
        bitness: 64,
        bytes: &original,
    };

    #[repr(align(16))]
    struct GuestStack([u8; 4096]);

    let mut stack = Box::new(GuestStack([0; 4096]));
    let stack_top = stack.0.as_mut_ptr().wrapping_add(stack.0.len()) as u64;

    let mut gate = X64Gate::new(X64GuestState {
        rcx: 17,
        rdx: 25,
        rsp: stack_top,
        ..X64GuestState::default()
    });

    let (entry, _) = gate.cache_shims();
    let mut cache = CodeCache::<ExecutableCode>::default();
    let page_bytes = page_size();
    let mut visited = Vec::new();

    let result = dispatch(
        GuestLocation {
            guest_ip: FIRST,
            bitness: 64,
        },
        |location| -> io::Result<BlockOutcome> {
            if location.guest_ip == STOP {
                return Ok(BlockOutcome::Finished(gate.guest().rax as u32));
            }

            if visited.len() >= 8 {
                return Err(io::Error::other("guest loop did not terminate"));
            }

            let source = region
                .bytes_at(location)
                .map_err(|error| io::Error::other(format!("code fetch failed: {error:?}")))?;

            let block = prepare_block_with_encoder(
                &mut cache,
                BlockSource {
                    bytes: source,
                    bitness: location.bitness,
                    guest_ip: location.guest_ip,
                },
                page_bytes,
                page_bytes,
                decode_one,
                CodeMemory::allocate,
                |block, bytes, cache_ip| {
                    encode_dispatch_block(
                        block,
                        bytes,
                        cache_ip,
                        &entry,
                        |body, bitness, source_ip, body_ip| {
                            relocate_block(body, bitness, source_ip, body_ip).map_err(|error| {
                                io::Error::other(format!("relocation failed: {error:?}"))
                            })
                        },
                        |site, code| match site.exit {
                            BlockExit::DirectJump { target } => {
                                code.extend_from_slice(&gate.exit_to(*target));
                                Ok(())
                            }
                            BlockExit::Conditional { taken, not_taken } => {
                                let fallthrough_exit = gate.exit_to(*not_taken);
                                let taken_exit = gate.exit_to(*taken);

                                emit_jcc_exit_x64(
                                    site.original_bytes,
                                    site.guest_ip,
                                    site.cache_ip,
                                    &fallthrough_exit,
                                    &taken_exit,
                                    code,
                                )
                            }
                            _ => Err(io::Error::other("unsupported block exit")),
                        },
                    )
                },
            )?;

            visited.push(location.guest_ip);

            // SAFETY: This fixture uses stack-neutral integer instructions.
            // Every generated path exits through this gate's matching shim.
            unsafe { gate.run(block.code.address()) };

            Ok(BlockOutcome::Continue(GuestLocation {
                guest_ip: gate.next_guest_ip(),
                bitness: location.bitness,
            }))
        },
    )?;

    assert_eq!(visited, [FIRST, LOOP_HEAD, LOOP_HEAD, LOOP_HEAD]);
    assert_eq!(gate.guest().rbx, 39);
    assert_eq!(gate.guest().rax, 39);
    assert_eq!(result, 39);

    Ok(())
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn runs_nested_guest_calls_on_the_guest_stack() -> std::io::Result<()> {
    const START: u64 = 0x1000;
    const STOP: u64 = 0x1018;

    let original = [
        0xE8, 0x03, 0, 0, 0, // 0x1000: call 0x1008
        0xEB, 0x11, // 0x1005: jmp 0x1018
        0x90, // 0x1007: padding
        0xE8, 0x05, 0, 0, 0, // 0x1008: call 0x1012
        0x48, 0x83, 0xC0, 0x02, // 0x100D: add rax, 2
        0xC3, // 0x1011: ret
        0xB8, 40, 0, 0, 0,    // 0x1012: mov eax, 40
        0xC3, // 0x1017: ret
    ];

    let region = CodeRegion {
        start_address: START,
        bitness: 64,
        bytes: &original,
    };

    #[repr(align(16))]
    struct GuestStack([u8; 4096]);

    let mut stack = Box::new(GuestStack([0; 4096]));
    let stack_top = stack.0.as_mut_ptr().wrapping_add(stack.0.len()) as u64;

    let mut gate = X64Gate::new(X64GuestState {
        rsp: stack_top,
        ..X64GuestState::default()
    });

    let (entry, _) = gate.cache_shims();
    let mut cache = CodeCache::<ExecutableCode>::default();
    let page_bytes = page_size();
    let mut trace = Vec::new();

    let result = dispatch(
        GuestLocation {
            guest_ip: START,
            bitness: 64,
        },
        |location| -> io::Result<BlockOutcome> {
            if location.guest_ip == STOP {
                return Ok(BlockOutcome::Finished(gate.guest().rax as u32));
            }

            if trace.len() >= 5 {
                return Err(io::Error::other("unexpected guest control flow"));
            }

            let source = region
                .bytes_at(location)
                .map_err(|error| io::Error::other(format!("code fetch failed: {error:?}")))?;

            let block = prepare_block_with_encoder(
                &mut cache,
                BlockSource {
                    bytes: source,
                    bitness: location.bitness,
                    guest_ip: location.guest_ip,
                },
                page_bytes,
                page_bytes,
                decode_one,
                CodeMemory::allocate,
                |block, bytes, cache_ip| {
                    encode_dispatch_block(
                        block,
                        bytes,
                        cache_ip,
                        &entry,
                        |body, bitness, source_ip, body_ip| {
                            relocate_block(body, bitness, source_ip, body_ip).map_err(|error| {
                                io::Error::other(format!("relocation failed: {error:?}"))
                            })
                        },
                        |site, code| {
                            match site.exit {
                                BlockExit::DirectJump { target } => {
                                    code.extend_from_slice(&gate.exit_to(*target));
                                }
                                BlockExit::DirectCall {
                                    target,
                                    return_address,
                                } => {
                                    code.extend_from_slice(&gate.call_to(*target, *return_address));
                                }
                                BlockExit::Return if site.original_bytes == b"\xC3" => {
                                    code.extend_from_slice(&gate.return_to_guest());
                                }
                                _ => return Err(io::Error::other("unsupported block exit")),
                            }

                            Ok(())
                        },
                    )
                },
            )?;

            // SAFETY: The known fixture pushes and pops at most two return
            // addresses on the live guest stack and uses matching gate shims.
            unsafe { gate.run(block.code.address()) };

            trace.push((location.guest_ip, gate.guest().rsp));

            Ok(BlockOutcome::Continue(GuestLocation {
                guest_ip: gate.next_guest_ip(),
                bitness: location.bitness,
            }))
        },
    )?;

    assert_eq!(
        trace,
        [
            (0x1000, stack_top - 8),
            (0x1008, stack_top - 16),
            (0x1012, stack_top - 8),
            (0x100D, stack_top),
            (0x1005, stack_top),
        ]
    );
    assert_eq!(result, 42);

    Ok(())
}
#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn follows_indirect_calls_from_register_and_memory() -> std::io::Result<()> {
    use isa::{decode_one, encode_indirect_call_target_x64, relocate_block};
    use mbdi_engine::{
        execution::dispatcher::{BlockOutcome, GuestLocation, dispatch},
        translation::{
            block::BlockExit,
            cache::CodeCache,
            encode::encode_dispatch_block,
            source::CodeRegion,
            translate::{BlockSource, prepare_block_with_encoder},
        },
    };
    use platform_windows::executable::{CodeMemory, ExecutableCode, page_size};
    use std::io;

    #[repr(C)]
    struct Program {
        code: [u8; 26],
        target_slot: u64,
    }

    #[repr(align(16))]
    struct GuestStack([u64; 512]);

    const _: () = assert!(std::mem::offset_of!(Program, target_slot) == 32);

    let mut program = Box::new(Program {
        code: [
            0xFF, 0xD0, // +0:  call rax
            0xEB, 0x16, // +2:  jmp +26
            0xFF, 0x54, 0x24, 0xF8, // +4:  call [rsp - 8]
            0x48, 0x83, 0xC0, 0x02, // +8:  add rax, 2
            0xC3, // +12: ret
            0xFF, 0x15, 0x0D, 0, 0, 0,    // +13: call [rip + 13], slot at +32
            0xC3, // +19: ret
            0xB8, 40, 0, 0, 0,    // +20: mov eax, 40
            0xC3, // +25: ret
        ],
        target_slot: 0,
    });

    let start = program.code.as_ptr() as u64;
    let stop = start + 26;
    program.target_slot = start + 20;

    let region = CodeRegion {
        start_address: start,
        bitness: 64,
        bytes: &program.code,
    };

    let mut stack = Box::new(GuestStack([0; 512]));
    stack.0[510] = start + 13;

    let stack_top = stack.0.as_mut_ptr().wrapping_add(stack.0.len()) as u64;
    let mut gate = X64Gate::new(X64GuestState {
        rax: start + 4,
        rsp: stack_top,
        ..X64GuestState::default()
    });

    let (entry, _) = gate.cache_shims();
    let mut cache = CodeCache::<ExecutableCode>::default();
    let page_bytes = page_size();
    let mut trace = Vec::new();

    let result = dispatch(
        GuestLocation {
            guest_ip: start,
            bitness: 64,
        },
        |location| -> io::Result<BlockOutcome> {
            if location.guest_ip == stop {
                return Ok(BlockOutcome::Finished(gate.guest().rax as u32));
            }

            if trace.len() >= 7 {
                return Err(io::Error::other("unexpected guest control flow"));
            }

            let source = region
                .bytes_at(location)
                .map_err(|error| io::Error::other(format!("code fetch failed: {error:?}")))?;

            let block = prepare_block_with_encoder(
                &mut cache,
                BlockSource {
                    bytes: source,
                    bitness: location.bitness,
                    guest_ip: location.guest_ip,
                },
                page_bytes,
                page_bytes,
                decode_one,
                CodeMemory::allocate,
                |block, bytes, cache_ip| {
                    encode_dispatch_block(
                        block,
                        bytes,
                        cache_ip,
                        &entry,
                        |body, bitness, source_ip, body_ip| {
                            relocate_block(body, bitness, source_ip, body_ip).map_err(|error| {
                                io::Error::other(format!("relocation failed: {error:?}"))
                            })
                        },
                        |site, code| {
                            match site.exit {
                                BlockExit::DirectJump { target } => {
                                    code.extend_from_slice(&gate.exit_to(*target));
                                }
                                BlockExit::IndirectCall { return_address } => {
                                    let load = encode_indirect_call_target_x64(
                                        site.original_bytes,
                                        site.guest_ip,
                                    )?;
                                    gate.emit_indirect_call(&load, *return_address, code);
                                }
                                BlockExit::Return if site.original_bytes == b"\xC3" => {
                                    code.extend_from_slice(&gate.return_to_guest());
                                }
                                _ => return Err(io::Error::other("unsupported block exit")),
                            }

                            Ok(())
                        },
                    )
                },
            )?;

            // SAFETY: The fixture uses a live guest stack and target slot.
            // Every block returns through matching gate shims.
            unsafe { gate.run(block.code.address()) };

            trace.push(location.guest_ip - start);

            Ok(BlockOutcome::Continue(GuestLocation {
                guest_ip: gate.next_guest_ip(),
                bitness: location.bitness,
            }))
        },
    )?;

    assert_eq!(trace, [0, 4, 13, 20, 19, 8, 2]);
    assert_eq!(gate.guest().rsp, stack_top);
    assert_eq!(result, 42);

    Ok(())
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn follows_indirect_jumps_without_pushing_a_return_address() -> std::io::Result<()> {
    use isa::{decode_one, encode_indirect_jump_target_x64, relocate_block};
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
    use std::io;

    #[repr(C)]
    struct Program {
        code: [u8; 22],
        target_slot: u64,
    }

    #[repr(align(16))]
    struct GuestStack([u64; 512]);

    struct TestRuntime {
        gate: X64Gate,
        start: u64,
        stop: u64,
        trace: Vec<(u64, u64)>,
    }

    impl CachedBlockRuntime<ExecutableCode> for TestRuntime {
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
                        BlockExit::DirectCall {
                            target,
                            return_address,
                        } => {
                            code.extend_from_slice(&self.gate.call_to(*target, *return_address));
                        }
                        BlockExit::IndirectJump => {
                            let load = encode_indirect_jump_target_x64(
                                site.original_bytes,
                                site.guest_ip,
                            )?;
                            self.gate.emit_indirect_jump(&load, code);
                        }
                        BlockExit::Return if site.original_bytes == b"\xC3" => {
                            code.extend_from_slice(&self.gate.return_to_guest());
                        }
                        _ => return Err(io::Error::other("unsupported block exit")),
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
            if self.trace.len() >= 5 {
                return Err(io::Error::other(format!(
                    "unexpected guest trace: {:?}",
                    self.trace,
                )));
            }

            // SAFETY: This fixture owns the guest stack and target slot.
            // Its blocks are published with the matching gate's shims.
            unsafe { self.gate.run(block.code.address()) };

            self.trace
                .push((location.guest_ip - self.start, self.gate.guest().rsp));

            let next_ip = self.gate.next_guest_ip();
            if next_ip == self.stop {
                return Ok(BlockOutcome::Finished(self.gate.guest().rax as u32));
            }

            Ok(BlockOutcome::Continue(GuestLocation {
                guest_ip: next_ip,
                bitness: location.bitness,
            }))
        }
    }

    const _: () = assert!(std::mem::offset_of!(Program, target_slot) == 24);

    let mut program = Box::new(Program {
        code: [
            0xE8, 0x03, 0, 0, 0, // +0:  call +8
            0xEB, 0x0F, // +5:  jmp +22
            0x90, // +7:  padding
            0xFF, 0xE1, // +8:  jmp rcx
            0xFF, 0x25, 0x08, 0, 0, 0, // +10: jmp [rip + 8], slot at +24
            0xB8, 42, 0, 0, 0,    // +16: mov eax, 42
            0xC3, // +21: ret
        ],
        target_slot: 0,
    });

    let start = program.code.as_ptr() as u64;
    program.target_slot = start + 16;

    let region = CodeRegion {
        start_address: start,
        bitness: 64,
        bytes: &program.code,
    };

    let mut stack = Box::new(GuestStack([0; 512]));
    let stack_top = stack.0.as_mut_ptr().wrapping_add(stack.0.len()) as u64;

    let mut runtime = TestRuntime {
        gate: X64Gate::new(X64GuestState {
            rcx: start + 10,
            rsp: stack_top,
            ..X64GuestState::default()
        }),
        start,
        stop: start + 22,
        trace: Vec::new(),
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

    assert_eq!(
        runtime.trace,
        [
            (0, stack_top - 8),
            (8, stack_top - 8),
            (10, stack_top - 8),
            (16, stack_top),
            (5, stack_top),
        ]
    );
    assert_eq!(result, 42);

    Ok(())
}
