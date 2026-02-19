#![no_main]

use leash::config::Config;
use leash::fuzzing::fuzz_write_into_corpus;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    if Config::from_yaml_str(&input).is_ok() {
        let _ = fuzz_write_into_corpus("config_parsing", data);
    }
});
