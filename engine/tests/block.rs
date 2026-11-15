use isa::{decode_one, relocate_block};
use mbdi_engine::translation::block::{BlockExit, build_block};
use mbdi_engine::translation::cache::CodeCache;
use platform_windows::executable::{CodeMemory, ExecutableCode,page_size};

#[test]
fn conditional_branch_ends_block() {
    let bytes = [0x90, 0x75, 0x05, 0x90];
    let block = build_block(&bytes, 64, 0x1000, decode_one).unwrap();

    assert_eq!(block.start_address, 0x1000);
    assert_eq!(block.bitness, 64);
    assert_eq!(block.instructions.len(), 2);

    match block.exit {
        BlockExit::Conditional { taken, not_taken } => {
            assert_eq!(taken, 0x1008);
            assert_eq!(not_taken, 0x1003);
        }
        other => panic!("Expected conditional exit, got {other:?}"),
    }
}

#[test]
fn relocated_jne_keeps_its_target() {
    let original = [0x90, 0x75, 0x05];
    let source_ip = 0x1000;
    let destination_ip = 0x5000;
    let relocated =
        relocate_block(&original, 64, source_ip, destination_ip).expect("block relocation failed");

    let first =
        decode_one(&relocated, 64, destination_ip).expect("failed to decode the relocated nop");

    let branch_offset = usize::from(first.length);
    let branch = decode_one(&relocated[branch_offset..], 64, first.next_address)
        .expect("failed to decode the relocated branch");

    assert_eq!(branch.address, 0x5001);
    assert_eq!(branch.direct_target, Some(0x1008));
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn executes_cached_block_twice() {
    let original = [0xB8, 42, 0, 0, 0, 0xC3]; // mov eax, 42; ret
    let mut cache = CodeCache::<ExecutableCode>::default();
    let mut translations = 0;
    let page_bytes=page_size();
    let mut allocation_attempts=0;
    
    let mut translate = || -> std::io::Result<_> {
        translations += 1;

        let block =
            build_block(&original, 64, 0x1000, decode_one).expect("block construction failed");
        
        let mut capacity=4;

        for _ in 0..2{
            allocation_attempts+=1;
            let memory=CodeMemory::allocate(capacity)?;

            let bytes=relocate_block(&original,64,0x1000,memory.address()).expect("relocation failed");
            if bytes.len() <=capacity{
                let code=memory.publish(&bytes)?;
                return Ok((code,block.exit));
            }
            capacity=bytes.len().div_ceil(page_bytes).checked_mul(page_bytes).ok_or_else(|| std::io::Error::other("code capacity overflow"))?;
        }
        Err(std::io::Error::other("relocated block does not fit after two attempts"))
    };

    for _ in 0..2 {
        let block = cache
            .get_or_translate(64, 0x1000, &mut translate)
            .expect("translation failed");

        let result = unsafe {
            let function: unsafe extern "C" fn() -> u32 =
                std::mem::transmute(block.code.address() as usize);
            function()
        };

        assert_eq!(result, 42);
    }

    assert_eq!(translations, 1);
    assert_eq!(allocation_attempts,2);
}
