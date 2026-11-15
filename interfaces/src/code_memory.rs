use std::io;

pub trait WritableCode {
    type Executable;
    fn address(&self) -> u64;
    fn publish(self, bytes: &[u8]) -> io::Result<Self::Executable>;
}
