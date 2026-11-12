use isa::{decode, decode_one};
use mbdi_engine::translation::block::build_block;
use object::{Architecture, BinaryFormat, Object, ObjectSection, SectionFlags};
use std::{env, error::Error, ffi::OsStr, path::Path};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os().skip(1);
    let usage = "Usage: mbdi-host inspect <file.exe>";
    if args.next().as_deref() != Some(OsStr::new("inspect")) {
        return Err(usage.into());
    }
    let path = args.next().ok_or(usage)?;
    if args.next().is_some() {
        return Err(usage.into());
    }
    inspect_pe(Path::new(&path))
}

fn inspect_pe(path: &Path) -> Result<(), Box<dyn Error>> {
    let data = std::fs::read(path)?;
    let pe = object::File::parse(data.as_slice())?;
    if pe.format() != BinaryFormat::Pe {
        return Err("File is not a pe!".into());
    }
    let bitness = match pe.architecture() {
        Architecture::X86_64 => 64,
        Architecture::I386 => 32,
        _ => return Err("Unsupported architecture!".into()),
    };
    let entry = pe.entry();
    if entry == 0 || entry == pe.relative_address_base() {
        return Err("File has no entry point!".into());
    }
    for section in pe.sections() {
        let SectionFlags::Coff { characteristics } = section.flags() else {
            continue;
        };

        if characteristics & object::pe::IMAGE_SCN_MEM_EXECUTE == 0 {
            continue;
        }

        let Some(offset) = entry.checked_sub(section.address()) else {
            continue;
        };

        if offset >= section.size() {
            continue;
        }

        let data = section.data()?;
        let start = usize::try_from(offset)?;
        let end = usize::try_from(section.size().min(data.len() as u64))?;
        let code = data
            .get(start..end)
            .filter(|bytes| !bytes.is_empty())
            .ok_or("Section has no code at entry point!")?;

        let block = build_block(code, bitness, entry, decode_one)
            .map_err(|e| format!("Failed to build block: {e:?}"))?;
        let block_len: usize = block
            .instructions
            .iter()
            .map(|instruction| usize::from(instruction.length))
            .sum();
        println!("File: {}", path.display());
        println!("PE: {bitness}-bit | entry {entry:#x}");
        println!("First block: {} instructions", block.instructions.len());

        for (address, assembly) in decode(&code[..block_len], bitness, entry)? {
            println!("{address:#x}: {assembly}");
        }
        println!("Exit:{:x?}", block.exit);
    }
    Err("Not in a executable section!".into())
}
