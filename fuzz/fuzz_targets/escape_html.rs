#![no_main]

use leash::alerts::escape_html;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    let _ = escape_html(&input);
});
