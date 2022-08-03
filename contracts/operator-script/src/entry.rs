// Import from `core` instead of from `std` since we are in no-std mode
use core::convert::TryInto;
use core::result::Result;

// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
use alloc::{vec, vec::Vec};

// Import CKB syscalls and structures
// https://nervosnetwork.github.io/ckb-std/riscv64imac-unknown-none-elf/doc/ckb_std/index.html
use blake2b_ref::{Blake2b, Blake2bBuilder};
use ckb_std::{
    ckb_constants::*,
    ckb_types::{bytes::Bytes, prelude::*},
    debug, dynamic_loading_c_impl,
    error::SysError,
    high_level::{load_script, load_witness_args, load_input, load_cell_type_hash, load_cell_capacity},
};

use crate::code_hashes;
use crate::error::Error;

const BLAKE2B_BLOCK_SIZE: usize = 32;
const BLAKE2B160_BLOCK_SIZE: usize = 20;

// #[link(name = "dl-c-impl", kind = "static")]
// extern "C" {
//     fn ckb_validate_type_id(type_id: *const u8) -> isize;
// }

fn new_blake2b() -> Blake2b {
    const CKB_HASH_PERSONALIZATION: &[u8] = b"ckb-default-hash";
    Blake2bBuilder::new(32)
        .personal(CKB_HASH_PERSONALIZATION)
        .build()
}

fn get_key_size(key_size_enum: u8) -> usize {
    let key_size = match key_size_enum {
        1 => 1024,
        2 => 2048,
        3 => 4096,
        _ => 0,
    };
    if key_size == 0 {
        panic!("wrong key size");
    };
    key_size
}

fn calculate_pub_key_hash(signature: &[u8], key_size: usize) -> Vec<u8> {
    let mut hash: Vec<u8> = Default::default();
    hash.resize(BLAKE2B_BLOCK_SIZE, 0);

    let mut blake2b = new_blake2b();
    blake2b.update(&signature[4..8]);
    blake2b.update(&signature[8..(8 + key_size / 8)]);
    blake2b.finalize(hash.as_mut_slice());
    hash.truncate(BLAKE2B160_BLOCK_SIZE);
    hash
}

fn calculate_rsa_info_length(key_size_enum: u8) -> usize {
    8 + get_key_size(key_size_enum) / 4
}

type DlContextType = dynamic_loading_c_impl::CKBDLContext<[u8; 128 * 1024]>;
/*
int validate_signature(void *prefilled_data, const uint8_t *signature_buffer,
size_t signature_size, const uint8_t *msg_buf,
size_t msg_size, uint8_t *output, size_t *output_len);
 */
type DlFnType = unsafe extern "C" fn(
    fill: *const u8,
    signature: *const u8,
    signature_size: usize,
    msg_buf: *const u8,
    msg_size: usize,
    output: *const u8,
    output_len: *const usize,
) -> isize;

pub fn main() -> Result<(), Error> {
    let script = load_script()?;
    let script_args: Bytes = script.args().raw_data();
    debug!("script args is {:?}", script_args);

    // let ret = unsafe { ckb_validate_type_id(script_args.as_ref().as_ptr()) };
    // if ret != 0 {
    //     return Err(Error::InvalidTypeId);
    // }
    verify_type_id(script_args.as_ref())?;
    // verify_charge(script_args.as_ref())?;

    Ok(())
}

fn verify_type_id(script_args: &[u8]) -> Result<(), Error> {
    if script_args.len() != 32 {
        debug!("script args is not 32");
        return Err(Error::InvalidTypeId);
    }
    if load_cell_capacity(1, Source::GroupInput).is_ok() {
        debug!("too many inputs");
        return Err(Error::InvalidTypeId);
    }
    if load_cell_capacity(1, Source::GroupOutput).is_ok() {
        debug!("too many outputs");
        return Err(Error::InvalidTypeId);
    }
    match load_cell_capacity(0, Source::GroupInput) {
        Ok(_) => {},
        Err(SysError::IndexOutOfBound) => {
            let first_cell_input = load_input(0, Source::Input)?;
            let script_hash = load_cell_type_hash(0, Source::GroupOutput)?.unwrap();
            let mut first_output_index = 0u64;
            let mut index = 0;
            loop {
                match load_cell_type_hash(index, Source::Output) {
                    Ok(Some(hash)) => {
                        if hash == script_hash {
                            first_output_index = index as u64;
                            break;
                        }
                    }
                    Ok(None) => {},
                    Err(err) => {
                        return Err(Error::InvalidTypeId);
                    }
                }
                index += 1;
            }

            let mut ret = [0; 32];
            let mut blake2b = new_blake2b();
            blake2b.update(first_cell_input.as_slice());
            blake2b.update(&first_output_index.to_le_bytes());
            blake2b.finalize(&mut ret);
            if &ret[..] != script_args {
                debug!("script args not match");
                return Err(Error::InvalidTypeId);
            }
        }
        Err(err) => {
            return Err(Error::InvalidTypeId);
        }
    }
    Ok(())
}

fn verify_charge(script_args: &[u8]) -> Result<(), Error> {
    let validate_signature_fn: dynamic_loading_c_impl::Symbol<DlFnType>;
    unsafe {
        let mut ctx = DlContextType::new();
        let lib = ctx
            .load(&code_hashes::CODE_HASH_SHARED_LIB)
            .expect("load shared lib");
        validate_signature_fn = lib
            .get(b"validate_signature")
            .expect("get function symbol validate_signature from dyanmic library");
    }

    // 0..8 => count(u64).to_le_bytes()
    // 8... => signature
    let proof: Bytes = load_witness_args(0, Source::GroupInput)?
        .input_type()
        .to_opt()
        .ok_or(Error::InvalidArgs1)?
        .unpack();
    if proof.len() < 8 + 8 {
        return Err(Error::InvalidArgs1);
    }
    let count = u64::from_le_bytes(proof.as_ref()[0..8].try_into().unwrap());
    let signature = &proof.as_ref()[8..];
    let signature_len = signature.len() - 8;

    //   typedef struct RsaInfo {
    //   uint8_t algorithm_id;
    //   uint8_t key_size;
    //   uint8_t padding;
    //   uint8_t md_type;
    //   uint32_t E;
    //   uint8_t N[PLACEHOLDER_SIZE];
    //   uint8_t sig[PLACEHOLDER_SIZE];
    // } RsaInfo;
    let algorithm_id = signature[0];
    assert_eq!(algorithm_id, 1);

    let key_size_enum = signature[1];
    let padding = signature[2];
    assert!(padding == 0 || padding == 1);
    let md_type = signature[3];
    assert!(md_type > 0);

    let key_size = get_key_size(key_size_enum);
    assert_eq!(key_size % 1024, 0);

    let info_len = calculate_rsa_info_length(key_size_enum);
    if signature.len() != info_len {
        return Err(Error::InvalidArgs1);
    }
    // hash: script.args + count(u64 little endian)
    let mut message = [0u8; BLAKE2B_BLOCK_SIZE];
    let mut blake2b = new_blake2b();
    blake2b.update(script_args.as_ref());
    blake2b.update(&proof.as_ref()[0..8]);
    blake2b.finalize(&mut message);

    unsafe {
        let ret = validate_signature_fn(
            core::ptr::null(),
            signature.as_ptr(),
            signature_len,
            message.as_ptr(),
            BLAKE2B_BLOCK_SIZE,
            core::ptr::null(),
            core::ptr::null(),
        );
        if ret != 0 {
            debug!("validate_signature() failed: {}", ret);
            return Err(Error::ValidateSignatureError);
        }
    }
    let pub_key_hash = calculate_pub_key_hash(signature, key_size);
    Ok(())
}
