// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;

// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
// use alloc::{vec, vec::Vec};

// Import CKB syscalls and structures
// https://nervosnetwork.github.io/ckb-std/riscv64imac-unknown-none-elf/doc/ckb_std/index.html
use ckb_std::{
    ckb_types::{bytes::Bytes, prelude::*},
    debug,
    high_level::load_script,
};

use crate::error::Error;

#[link(name = "dl-c-impl", kind = "static")]
extern "C" {
    fn ckb_validate_type_id(type_id: *const u8) -> isize;
}

pub fn main() -> Result<(), Error> {
    // remove below examples and write your code here

    let script = load_script()?;
    let args: Bytes = script.args().unpack();
    debug!("script args is {:?}", args);

    let ret = unsafe { ckb_validate_type_id(args.as_ref().as_ptr()) };
    debug!("ret: {}", ret);

    Ok(())
}
