#![no_main]
use libfuzzer_sys::fuzz_target;

use xori::analysis::analyze::analyze;
use xori::configuration::*;
use xori::disasm::*;

fuzz_target!(|data: (u8, Vec<u8>)| {
    let (m32, mut bytes) = data;
    let mode = match m32 % 3 {
        0 => Mode::Mode16,
        1 => Mode::Mode32,
        _ => Mode::Mode64,
    };

    let config_map = Config::new();
    analyze(&Arch::ArchX86, &mode, &mut bytes, &config_map);
});
