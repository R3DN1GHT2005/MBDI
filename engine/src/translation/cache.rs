use std::collections::{HashMap, hash_map::Entry};

use super::block::BlockExit;

pub struct CachedBlock<C> {
    pub guest_ip: u64,
    pub bitness: u32,
    pub code: C,
    pub exit: BlockExit,
}

pub struct CodeCache<C> {
    blocks: HashMap<(u32, u64), CachedBlock<C>>,
}

impl<C> Default for CodeCache<C> {
    fn default() -> Self {
        Self {
            blocks: HashMap::new(),
        }
    }
}

impl<C> CodeCache<C> {
    pub fn get(&self, bitness: u32, guest_ip: u64) -> Option<&CachedBlock<C>> {
        self.blocks.get(&(bitness, guest_ip))
    }

    pub fn insert(&mut self, block: CachedBlock<C>) -> Option<CachedBlock<C>> {
        self.blocks.insert((block.bitness, block.guest_ip), block)
    }

    pub fn get_or_translate<E>(
        &mut self,
        bitness: u32,
        guest_ip: u64,
        translate: impl FnOnce() -> Result<(C, BlockExit), E>,
    ) -> Result<&CachedBlock<C>, E> {
        match self.blocks.entry((bitness, guest_ip)) {
            Entry::Occupied(entry) => Ok(entry.into_mut()),
            Entry::Vacant(entry) => {
                let (code, exit) = translate()?;
                Ok(entry.insert(CachedBlock {
                    guest_ip,
                    bitness,
                    code,
                    exit,
                }))
            }
        }
    }
}
