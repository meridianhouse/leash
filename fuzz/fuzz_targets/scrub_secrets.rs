#![no_main]

use leash::alerts::scrub_secrets;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    let _ = scrub_secrets(&input);
});
