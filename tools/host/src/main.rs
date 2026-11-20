use isa::{decode, decode_one};
use mbdi_engine::translation::block::build_block;
use mbdi_engine::{
    execution::dispatcher::GuestLocation,
    translation::source::{CodeImage, CodeRegion, CodeSource},
};
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
    let file_bytes = std::fs::read(path)?;
    let pe = object::File::parse(file_bytes.as_slice())?;

    if pe.format() != BinaryFormat::Pe {
        return Err("File is not a PE image".into());
    }

    let bitness = match pe.architecture() {
        Architecture::X86_64 => 64,
        Architecture::I386 => 32,
        _ => return Err("Unsupported architecture".into()),
    };

    let entry = pe.entry();
    if entry == 0 || entry == pe.relative_address_base() {
        return Err("File has no entry point".into());
    }

    let mut regions = Vec::new();

    for section in pe.sections() {
        let SectionFlags::Coff { characteristics } = section.flags() else {
            continue;
        };

        if characteristics & object::pe::IMAGE_SCN_MEM_EXECUTE == 0 {
            continue;
        }

        let data = section.data()?;
        let length = section.size().min(data.len() as u64) as usize;

        if length == 0 {
            continue;
        }

        regions.push(CodeRegion {
            start_address: section.address(),
            bitness,
            bytes: &data[..length],
        });
    }

    let location = GuestLocation {
        guest_ip: entry,
        bitness,
    };

    let image = CodeImage {
        entry: location,
        regions: &regions,
    };

    let code = image
        .bytes_at(location)
        .map_err(|error| format!("Cannot read code at {:#x}: {error:?}", location.guest_ip))?;

    let block = build_block(code, bitness, entry, decode_one)
        .map_err(|error| format!("Failed to build block: {error:?}"))?;

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

    println!("Exit: {:x?}", block.exit);
    Ok(())
}
