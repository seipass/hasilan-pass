#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(imported) = hasilan_bitwarden_compat::import_json(data) {
        let exported = hasilan_bitwarden_compat::export_json(&imported)
            .expect("an imported, bounded vault must remain exportable");
        let _ = hasilan_bitwarden_compat::import_json(&exported)
            .expect("canonical exporter output must be importable");
    }
});

