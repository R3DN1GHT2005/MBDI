use std::{arch::naked_asm, cell::UnsafeCell, io};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct X86GuestState {
    pub eax: u32,
    pub ecx: u32,
    pub edx: u32,
    pub ebx: u32,
    pub esp: u32,
    pub ebp: u32,
    pub esi: u32,
    pub edi: u32,
    pub eflags: u32,
}

#[repr(C)]
struct X86GateFrame {
    guest: X86GuestState,
    host_esp: u32,
    cache_entry: u32,
    leave_entry: u32,
}

const _: () = {
    assert!(std::mem::offset_of!(X86GateFrame, guest) == 0);
    assert!(std::mem::offset_of!(X86GuestState, esp) == 16);
    assert!(std::mem::offset_of!(X86GuestState, eflags) == 32);
    assert!(std::mem::offset_of!(X86GateFrame, host_esp) == 36);
    assert!(std::mem::offset_of!(X86GateFrame, cache_entry) == 40);
    assert!(std::mem::offset_of!(X86GateFrame, leave_entry) == 44);
};

pub struct X86Gate {
    frame: Box<UnsafeCell<X86GateFrame>>,
}

impl X86Gate {
    pub fn new(guest: X86GuestState) -> Self {
        Self {
            frame: Box::new(UnsafeCell::new(X86GateFrame {
                guest,
                host_esp: 0,
                cache_entry: 0,
                leave_entry: 0,
            })),
        }
    }
    pub fn guest(&self) -> X86GuestState {
        unsafe { (*self.frame.get()).guest }
    }
    pub fn cache_shims(&self) -> ([u8; 5], [u8; 13]) {
        let frame_address = (self.frame.get() as u32).to_le_bytes();

        // mov eax, [guest.eax]
        let mut entry = [0xA1, 0, 0, 0, 0];
        entry[1..5].copy_from_slice(&frame_address);

        let mut exit = [0; 13];

        // mov [guest.eax], eax
        exit[0] = 0xA3;
        exit[1..5].copy_from_slice(&frame_address);

        // mov eax, frame_address
        exit[5] = 0xB8;
        exit[6..10].copy_from_slice(&frame_address);

        // jmp dword ptr [eax + 44]
        exit[10..].copy_from_slice(&[0xFF, 0x60, 0x2C]);

        (entry, exit)
    }
    /// # Safety
    /// `cache_entry` must point to live code generated with this gate's shims.
    /// The guest stack and memory must remain valid. The block must use the
    /// supported integer state and reach the exit shim without faults or unwind.
    pub unsafe fn run(&mut self, cache_entry: u64) -> io::Result<()> {
        let cache_entry = u32::try_from(cache_entry).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "cache address exceeds x86 range",
            )
        })?;

        unsafe { enter_x86(self.frame.get(), cache_entry) };
        Ok(())
    }
}

#[unsafe(naked)]
unsafe extern "C" fn enter_x86(_frame: *mut X86GateFrame, _cache_entry: u32) {
    naked_asm!(
        // Save the host's flags and nonvolatile registers on S1.
        "pushfd",
        "push ebx",
        "push ebp",
        "push esi",
        "push edi",
        // Five pushes moved the cdecl arguments by 20 bytes.
        "mov eax, [esp + 24]",
        "mov edx, [esp + 28]",
        "mov [eax + 36], esp",
        "mov [eax + 40], edx",
        "lea edx, [2f]",
        "mov [eax + 44], edx",
        // Restore guest CF, PF, AF, ZF, SF and OF.
        "pushfd",
        "pop ecx",
        "and ecx, 0xfffff72a",
        "mov edx, [eax + 32]",
        "and edx, 0x8d5",
        "or ecx, edx",
        "push ecx",
        "popfd",
        "mov ecx, [eax + 4]",
        "mov edx, [eax + 8]",
        "mov ebx, [eax + 12]",
        "mov ebp, [eax + 20]",
        "mov esi, [eax + 24]",
        "mov edi, [eax + 28]",
        "mov esp, [eax + 16]",
        "jmp dword ptr [eax + 40]",
        // The cache exit saved guest EAX and put the frame pointer in EAX.
        "2:",
        "mov [eax + 4], ecx",
        "mov [eax + 8], edx",
        "mov [eax + 12], ebx",
        "mov [eax + 16], esp",
        "mov [eax + 20], ebp",
        "mov [eax + 24], esi",
        "mov [eax + 28], edi",
        "mov esp, [eax + 36]",
        "pushfd",
        "pop dword ptr [eax + 32]",
        "pop edi",
        "pop esi",
        "pop ebp",
        "pop ebx",
        "popfd",
        "ret",
    );
}
