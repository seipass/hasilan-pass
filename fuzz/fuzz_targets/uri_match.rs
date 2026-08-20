#![no_main]

use hasilan_vault::{UriMatchType, uri_matches};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let Ok(strategy) = UriMatchType::try_from(data[0] % 8) else {
        return;
    };
    let text = &data[2..];
    let split_at = usize::from(data[1]) % (text.len() + 1);
    let (saved, candidate) = text.split_at(split_at);
    let (Ok(saved), Ok(candidate)) = (
        std::str::from_utf8(saved),
        std::str::from_utf8(candidate),
    ) else {
        return;
    };
    drop(uri_matches(saved, candidate, strategy));
});

