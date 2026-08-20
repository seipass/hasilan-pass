#![no_main]

use hasilan_vault::VaultItem;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(item) = serde_json::from_slice::<VaultItem>(data) {
        let canonical = serde_json::to_vec(&item).expect("a parsed vault item must serialize");
        let _: VaultItem =
            serde_json::from_slice(&canonical).expect("serialized vault items must parse");
    }
});

