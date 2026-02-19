#![no_main]

use leash::alerts::escape_html;
use leash::fuzzing::fuzz_write_into_corpus;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    let output = escape_html(&input);
    if output != input {
        let _ = fuzz_write_into_corpus("escape_html", data);
    }
});
