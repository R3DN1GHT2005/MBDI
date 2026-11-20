#![cfg(all(windows, target_arch = "x86_64"))]

use std::io;

use isa::decode_one;
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
    use platform_windows::{
        executable::{CodeMemory, ExecutableCode, page_size},
        x64_gate::{X64Gate, X64GuestState},
    };

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
