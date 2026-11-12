use isa::{decode_one, relocate_block};
use mbdi_engine::translation::block::{BlockExit, build_block};

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
