#![no_main]

use libfuzzer_sys::fuzz_target;
use wiry_core::packet::Packet;
use wiry_fuzz::all_protos;

fuzz_target!(|data: &[u8]| {
    let Some((sel, body)) = data.split_first() else {
        return;
    };
    let protos = all_protos();
    let link = protos[*sel as usize % protos.len()];

    let mut first = Packet::dissect(body.to_vec(), link);
    wiry_fuzz::check_spans(&first);
    // Without this `to_bytes` is a no-op and the property is vacuous.
    first.mark_all_dirty();
    let bytes = first.to_bytes().to_vec();
    assert_eq!(bytes.len(), body.len(), "serialising changed the length");

    let mut second = Packet::dissect(bytes.clone(), link);
    wiry_fuzz::check_spans(&second);
    second.mark_all_dirty();
    let bytes2 = second.to_bytes().to_vec();

    assert_eq!(
        first.layers(),
        second.layers(),
        "layer chain changed after re-serialising"
    );
    assert_eq!(bytes, bytes2, "serialisation is not a fixed point");
});
