use mbdi_interfaces::WritableCode;
use std::mem::MaybeUninit;
use std::{io, ptr, ptr::NonNull};
use windows_sys::Win32::System::{
    Diagnostics::Debug::FlushInstructionCache,
    Memory::{
        MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, VirtualAlloc,
        VirtualFree, VirtualProtect,
    },
    SystemInformation::{GetSystemInfo, SYSTEM_INFO},
    Threading::GetCurrentProcess,
};

pub struct CodeMemory {
    base: NonNull<u8>,
    capacity: usize,
}

pub struct ExecutableCode {
    memory: CodeMemory,
}

impl CodeMemory {
    pub fn allocate(capacity: usize) -> io::Result<Self> {
        if capacity == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "code allocation must be non-empty",
            ));
        }
        let base = unsafe {
            VirtualAlloc(
                ptr::null(),
                capacity,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE,
            )
        };
        let base = NonNull::new(base.cast::<u8>()).ok_or_else(io::Error::last_os_error)?;
        Ok(Self { base, capacity })
    }
    pub fn address(&self) -> u64 {
        self.base.as_ptr() as u64
    }
    pub fn publish(self, bytes: &[u8]) -> io::Result<ExecutableCode> {
        if bytes.is_empty() || bytes.len() > self.capacity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "generated code does not fit in the allocation",
            ));
        }
        let mut old_protection = 0;
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), self.base.as_ptr(), bytes.len());
            if VirtualProtect(
                self.base.as_ptr().cast(),
                self.capacity,
                PAGE_EXECUTE_READ,
                &mut old_protection,
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            if FlushInstructionCache(GetCurrentProcess(), self.base.as_ptr().cast(), bytes.len())
                == 0
            {
                return Err(io::Error::last_os_error());
            }
        };
        Ok(ExecutableCode { memory: self })
    }
}

pub fn page_size() -> usize {
    let mut info = MaybeUninit::<SYSTEM_INFO>::uninit();
    unsafe {
        GetSystemInfo(info.as_mut_ptr());
        info.assume_init().dwPageSize as usize
    }
}

impl ExecutableCode {
    pub fn address(&self) -> u64 {
        self.memory.address()
    }
}

impl Drop for CodeMemory {
    fn drop(&mut self) {
        unsafe {
            VirtualFree(self.base.as_ptr().cast(), 0, MEM_RELEASE);
        }
    }
}

impl WritableCode for CodeMemory {
    type Executable = ExecutableCode;
    fn address(&self) -> u64 {
        CodeMemory::address(self)
    }
    fn publish(self, bytes: &[u8]) -> io::Result<Self::Executable> {
        CodeMemory::publish(self, bytes)
    }
}
