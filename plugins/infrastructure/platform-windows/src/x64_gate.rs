use std::arch::global_asm;

global_asm!(include_str!("asm\\x64_gate.S"));

#[repr(C)]
#[derive(Debug, Default)]
pub struct X64GuestState {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rflags: u64,
}

#[repr(C)]
struct GateFrame {
    guest: X64GuestState,
    host_rsp: u64,
    cache_entry: u64,
    next_guest_ip: u64,
}

const _: () = {
    assert!(std::mem::offset_of!(X64GuestState, rflags) == 128);
    assert!(std::mem::offset_of!(GateFrame, host_rsp) == 136);
    assert!(std::mem::offset_of!(GateFrame, cache_entry) == 144);
    assert!(std::mem::offset_of!(GateFrame, next_guest_ip) == 152);
};

unsafe extern "system" {
    fn mbdi_x64_enter(frame: *mut GateFrame, cache_entry: u64);
    fn mbdi_x64_leave();
}

pub struct X64Gate {
    frame: Box<GateFrame>,
}

impl X64Gate {
    pub fn new(guest: X64GuestState) -> Self {
        Self {
            frame: Box::new(GateFrame {
                guest,
                host_rsp: 0,
                cache_entry: 0,
                next_guest_ip: 0,
            }),
        }
    }

    pub fn next_guest_ip(&self) -> u64 {
        self.frame.next_guest_ip
    }

    pub fn guest(&self) -> &X64GuestState {
        &self.frame.guest
    }

    pub fn exit_to(&self, guest_ip: u64) -> [u8; 54] {
        let (_, leave) = self.cache_shims();
        let next_ip_slot = std::ptr::addr_of!(self.frame.next_guest_ip) as u64;
        let mut exit = [0; 54];

        // Save guest RAX before using it as scratch.
        exit[..10].copy_from_slice(&leave[..10]);

        // mov rax, guest_ip
        exit[10..12].copy_from_slice(&[0x48, 0xB8]);
        exit[12..20].copy_from_slice(&guest_ip.to_le_bytes());

        // mov [absolute address of next_guest_ip], rax
        exit[20..22].copy_from_slice(&[0x48, 0xA3]);
        exit[22..30].copy_from_slice(&next_ip_slot.to_le_bytes());

        // Load the GateFrame pointer and jump to mbdi_x64_leave.
        exit[30..].copy_from_slice(&leave[10..]);

        exit
    }

    pub fn cache_shims(&self) -> ([u8; 10], [u8; 34]) {
        let frame = self.frame.as_ref() as *const GateFrame as u64;
        let leave = mbdi_x64_leave as *const () as u64;

        // mov rax, [absolute address of guest.rax]
        let mut entry = [0; 10];
        entry[..2].copy_from_slice(&[0x48, 0xA1]);
        entry[2..].copy_from_slice(&frame.to_le_bytes());

        let mut exit = [0; 34];

        // mov [absolute address of guest.rax], rax
        exit[..2].copy_from_slice(&[0x48, 0xA3]);
        exit[2..10].copy_from_slice(&frame.to_le_bytes());

        // mov rax, address of GateFrame
        exit[10..12].copy_from_slice(&[0x48, 0xB8]);
        exit[12..20].copy_from_slice(&frame.to_le_bytes());

        // jmp [rip + 0], followed by the address of mbdi_x64_leave
        exit[20..26].copy_from_slice(&[0xFF, 0x25, 0, 0, 0, 0]);
        exit[26..].copy_from_slice(&leave.to_le_bytes());

        (entry, exit)
    }

    /// # Safety
    /// `cache_entry` must point to live executable code built with this gate's
    /// entry and exit shims. The guest must have a valid stack. The block must
    /// stay within the controlled integer profile and reach its exit shim
    /// without faults or external control transfers.
    pub unsafe fn run(&mut self, cache_entry: u64) {
        unsafe { mbdi_x64_enter(&mut *self.frame, cache_entry) };
    }
}
