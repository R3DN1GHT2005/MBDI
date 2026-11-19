use crate::execution::dispatcher::GuestLocation;

pub struct CodeRegion<'a> {
    pub start_address: u64,
    pub bitness: u32,
    pub bytes: &'a [u8],
}

#[derive(Debug, PartialEq, Eq)]
pub enum SourceError {
    ModeMismatch,
    AddressOutsideRegion,
    AmbigousAddress,
}

impl CodeRegion<'_> {
    pub fn bytes_at(&self, location: GuestLocation) -> Result<&[u8], SourceError> {
        if location.bitness != self.bitness {
            return Err(SourceError::ModeMismatch);
        }
        let offset = location
            .guest_ip
            .checked_sub(self.start_address)
            .ok_or(SourceError::AddressOutsideRegion)?;
        let offset = usize::try_from(offset).map_err(|_| SourceError::AddressOutsideRegion)?;
        if offset >= self.bytes.len() {
            return Err(SourceError::AddressOutsideRegion);
        }
        Ok(&self.bytes[offset..])
    }
}

pub trait CodeSource {
    fn entry(&self) -> GuestLocation;
    fn bytes_at(&self, location: GuestLocation) -> Result<&[u8], SourceError>;
}

impl CodeSource for CodeRegion<'_> {
    fn entry(&self) -> GuestLocation {
        GuestLocation {
            guest_ip: self.start_address,
            bitness: self.bitness,
        }
    }
    fn bytes_at(&self, location: GuestLocation) -> Result<&[u8], SourceError> {
        CodeRegion::bytes_at(self, location)
    }
}

pub struct CodeImage<'a> {
    pub entry: GuestLocation,
    pub regions: &'a [CodeRegion<'a>],
}

impl CodeSource for CodeImage<'_> {
    fn entry(&self) -> GuestLocation {
        self.entry
    }
    fn bytes_at(&self, location: GuestLocation) -> Result<&[u8], SourceError> {
        let mut found = None;
        for region in self.regions {
            if let Ok(bytes) = region.bytes_at(location) {
                if found.is_some() {
                    return Err(SourceError::AmbigousAddress);
                }
                found = Some(bytes);
            }
        }
        found.ok_or(SourceError::AddressOutsideRegion)
    }
}
