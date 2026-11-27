#![cfg(all(windows, target_arch = "x86_64"))]

use mbdi_arch_runtime::x64_gate::X64GuestState;
use mbdi_engine::translation::source::CodeRegion;
use mbdi_host::windows_x64::run_x64_region;

#[test]
fn runs_a_region_through_the_shared_x64_adapter() -> std::io::Result<()> {
    #[repr(C)]
    struct Program {
        code: [u8; 27],
        target_slot: u64,
    }

    #[repr(align(16))]
    struct GuestStack([u64; 512]);

    const _: () = assert!(std::mem::offset_of!(Program, target_slot) == 32);

    let mut program = Box::new(Program {
        code: [
            0xE8, 0x03, 0, 0, 0, // +0:  call +8
            0xEB, 0x14, // +5:  jmp +27
            0x90, // +7:  padding
            0xFF, 0xE1, // +8:  jmp rcx
            0xFF, 0x25, 0x10, 0, 0, 0, // +10: jmp [rip + 16]
            0x48, 0xB8, 0x2A, 0, 0, 0, 1, 0, 0, 0,    // +16: mov rax, 0x10000002a
            0xC3, // +26: ret
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
    let guest = X64GuestState {
        rcx: start + 10,
        rsp: stack_top,
        ..X64GuestState::default()
    };

    // SAFETY: The fixture owns the stack and target slot for the whole run.
    let result = unsafe { run_x64_region(&region, guest, start + 27, 5) }?;

    assert_eq!(result, 0x1_0000_002A);
    Ok(())
}
