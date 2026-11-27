#![cfg(all(windows, target_arch = "x86"))]

use mbdi_arch_runtime::x86_gate::X86GuestState;
use mbdi_engine::translation::source::CodeRegion;
use mbdi_host::windows_x86::run_x86_region;

#[test]
fn carries_the_guest_stack_across_two_x86_blocks() -> std::io::Result<()> {
    const START: u64 = 0x1000;
    const STOP: u64 = 0x100E;

    let bytes = [
        0xB8, 40, 0, 0, 0,    // 0x1000: mov eax, 40
        0x50, // 0x1005: push eax
        0xEB, 0,    // 0x1006: jmp 0x1008
        0x5A, // 0x1008: pop edx
        0x8D, 0x42, 2, // 0x1009: lea eax, [edx + 2]
        0xEB, 0, // 0x100C: jmp 0x100E
    ];

    let region = CodeRegion {
        start_address: START,
        bitness: 32,
        bytes: &bytes,
    };

    let mut stack = Box::new([0_u32; 512]);
    let stack_top = stack.as_mut_ptr().wrapping_add(stack.len()) as u32;
    let guest = X86GuestState {
        esp: stack_top,
        ..X86GuestState::default()
    };

    // SAFETY: The fixture owns its guest stack and uses one balanced push/pop.
    let result = unsafe { run_x86_region(&region, guest, STOP, 2) }?;

    assert_eq!(result, 42);
    assert_eq!(stack[511], 40);
    Ok(())
}
