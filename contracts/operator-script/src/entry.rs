// Import from `core` instead of from `std` since we are in no-std mode
use core::convert::TryInto;
use core::result::Result;

// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
use alloc::vec::Vec;

// Import CKB syscalls and structures
// https://nervosnetwork.github.io/ckb-std/riscv64imac-unknown-none-elf/doc/ckb_std/index.html
use blake2b_ref::{Blake2b, Blake2bBuilder};
use ckb_std::{
    ckb_constants::*,
    ckb_types::{bytes::Bytes, prelude::*},
    debug, dynamic_loading_c_impl,
    error::SysError,
    high_level::*,
    since::{LockValue, Since},
};

use crate::code_hashes;
use crate::error::Error;

const BLAKE2B_BLOCK_SIZE: usize = 32;
const BLAKE2B160_BLOCK_SIZE: usize = 20;
const OWNER_OFFSET: usize = 8 + 8 + 8 + 20 + 32;
const MEMBER_LEN_OFFSET: usize = OWNER_OFFSET + 20;

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
    // pubkey.E
    blake2b.update(&signature[4..8]);
    // pubkey.N
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

    let is_create = verify_type_id(script_args.as_ref())?;
    if is_create {
        verify_create()?;
    } else {
        let input_data = load_cell_data(0, Source::GroupInput)?;
        let output_data = load_cell_data(0, Source::GroupOutput)?;
        // data frame:
        //   4    bytes => action type
        //   rest bytes => up to specific action
        let witness_input: Bytes = load_witness_args(0, Source::GroupInput)?
            .input_type()
            .to_opt()
            .ok_or(Error::InvalidArgs)?
            .unpack();
        let witness_input_slice = witness_input.as_ref();
        let action = u32::from_le_bytes(witness_input_slice[0..4].try_into().unwrap());
        match action {
            1 => verify_charge(
                script_args.as_ref(),
                &witness_input_slice[0..4],
                &input_data,
                &output_data,
            )?,
            2 => verify_extend_timelock(
                script_args.as_ref(),
                &witness_input_slice[0..4],
                &input_data,
                &output_data,
            )?,
            _ => panic!("invalid action"),
        }
    }

    Ok(())
}

// Return if the cell is newly created
fn verify_type_id(script_args: &[u8]) -> Result<bool, Error> {
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
    let mut is_create = false;
    match load_cell_capacity(0, Source::GroupInput) {
        Ok(_) => {}
        Err(SysError::IndexOutOfBound) => {
            is_create = true;
            let first_cell_input = load_input(0, Source::Input)?;
            let script_hash = load_cell_type_hash(0, Source::GroupOutput)?.unwrap();
            let first_output_index: u64;
            let mut index = 0;
            loop {
                match load_cell_type_hash(index, Source::Output) {
                    Ok(Some(hash)) => {
                        if hash == script_hash {
                            debug!("match output index: {}", index);
                            first_output_index = index as u64;
                            break;
                        }
                    }
                    Ok(None) => {}
                    Err(_err) => {
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
        Err(_err) => {
            return Err(Error::InvalidTypeId);
        }
    }
    Ok(is_create)
}

// Cell Data Frame:
//   8  bytes => current message count (u64 little endian)
//   8  bytes => one message price (u64 little endian, shannons/item)
//   8  bytes => time lock (utc timestamp, u64 little endian)
//   20 bytes => room host rsa pubkey blake160
//   32 bytes => room host lock script hash
//   20 bytes => room owner rsa pubkey blake160
//   2  bytes => room member length (little endian)
//   20 * n bytes => room members rsa pubkey blake160
fn verify_create() -> Result<(), Error> {
    let cell_data = load_cell_data(0, Source::GroupOutput)?;
    let current_count = u64::from_le_bytes(cell_data[0..8].try_into().unwrap());
    if current_count != 0 {
        debug!("init count not zero");
        return Err(Error::InvalidCellData);
    }
    let price = u64::from_le_bytes(cell_data[8..16].try_into().unwrap());
    if price == 0 {
        debug!("zero price");
        return Err(Error::InvalidCellData);
    }
    let offset = MEMBER_LEN_OFFSET;
    let member_len = u16::from_le_bytes(cell_data[offset..offset + 2].try_into().unwrap());
    if cell_data.len() != (offset + 2 + member_len as usize * 20) {
        debug!("invalid cell data length: {}", cell_data.len());
        return Err(Error::InvalidCellData);
    }
    Ok(())
}

fn verify_charge(
    script_args: &[u8],
    witness_input: &[u8],
    input_data: &[u8],
    output_data: &[u8],
) -> Result<(), Error> {
    let prev_count = u64::from_le_bytes(input_data[0..8].try_into().unwrap());
    let next_count = u64::from_le_bytes(output_data[0..8].try_into().unwrap());
    if next_count <= prev_count {
        return Err(Error::InvalidCount);
    }
    if input_data[8..] != output_data[8..] {
        debug!("data field other then count can not change");
        return Err(Error::InvalidCellData);
    }
    let price = u64::from_le_bytes(input_data[8..16].try_into().unwrap());
    let capacity_change = price.checked_mul(next_count - prev_count).unwrap();

    let input_capacity = load_cell_capacity(0, Source::GroupInput)?;
    let output_capacity = load_cell_capacity(0, Source::GroupInput)?;
    if input_capacity - output_capacity != capacity_change {
        debug!("invalid owner capacity change");
        return Err(Error::InvalidCharge);
    }

    let host_lock_hash = &input_data[44..44 + 32];
    let mut host_input_total = 0u64;
    let mut host_output_total = 0u64;
    for source in [Source::Input, Source::Output] {
        let mut index = 0;
        loop {
            let lock_hash = match load_cell_lock_hash(index, source) {
                Ok(hash) => hash,
                Err(SysError::IndexOutOfBound) => {
                    break;
                }
                Err(err) => {
                    return Err(err.into());
                }
            };
            if &lock_hash[..] == host_lock_hash {
                let capacity = load_cell_capacity(index, source)?;
                if source == Source::Input {
                    host_input_total += capacity;
                } else {
                    host_output_total += capacity;
                }
            }
            index += 1;
        }
    }
    if host_output_total - host_input_total != capacity_change {
        debug!("invalid host capacity change");
        return Err(Error::InvalidCharge);
    }

    // hash:
    //   * script.args
    //   * count(u64 little endian)
    let mut message = [0u8; BLAKE2B_BLOCK_SIZE];
    let mut blake2b = new_blake2b();
    blake2b.update(script_args.as_ref());
    blake2b.update(&output_data[0..8]);
    blake2b.finalize(&mut message);

    verify_rsa_signature(&message, witness_input, input_data, false)
}

fn verify_extend_timelock(
    script_args: &[u8],
    witness_input: &[u8],
    input_data: &[u8],
    output_data: &[u8],
) -> Result<(), Error> {
    let prev_ts = u64::from_le_bytes(input_data[16..24].try_into().unwrap());
    let next_ts = u64::from_le_bytes(output_data[16..24].try_into().unwrap());
    if next_ts <= prev_ts {
        debug!("next timelock value must greater than previous timelock");
        return Err(Error::InvalidTimelock);
    }
    // TODO: allow change host/members/price
    if input_data[0..16] != output_data[0..16] || input_data[24..] != output_data[24..] {
        debug!("data field other then count can not change");
        return Err(Error::InvalidCellData);
    }

    let since_value = load_input_since(0, Source::GroupInput)?;
    let since = Since::new(since_value);
    if !since.is_absolute() {
        debug!("must use absolute since");
        return Err(Error::InvalidSince);
    }
    let lock_value = since.extract_lock_value().unwrap();
    match lock_value {
        LockValue::Timestamp(value) => {
            if value < prev_ts {
                debug!("time not reached");
                return Err(Error::InvalidSince);
            }
        }
        _ => {
            debug!("must use timestamp since");
            return Err(Error::InvalidSince);
        }
    }

    // hash:
    //   * script.args
    //   * next time lock(u64 little endian)
    let mut message = [0u8; BLAKE2B_BLOCK_SIZE];
    let mut blake2b = new_blake2b();
    blake2b.update(script_args.as_ref());
    blake2b.update(&output_data[16..24]);
    blake2b.finalize(&mut message);

    verify_rsa_signature(&message, witness_input, input_data, true)
}

fn verify_rsa_signature(
    message: &[u8; 32],
    witness_input: &[u8],
    input_data: &[u8],
    owner_only: bool,
) -> Result<(), Error> {
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

    let signature = witness_input;
    let signature_len = signature.len();

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
        return Err(Error::InvalidArgs);
    }
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
            return Err(Error::InvalidSignature);
        }
    }
    let pub_key_hash = calculate_pub_key_hash(signature, key_size);
    let owner_pubkey = &input_data[OWNER_OFFSET..OWNER_OFFSET + 20];
    if &pub_key_hash == owner_pubkey {
        return Ok(());
    } else if owner_only {
        return Err(Error::InvalidSignature);
    } else {
        let offset = MEMBER_LEN_OFFSET;
        let member_len = u16::from_le_bytes(input_data[offset..offset + 2].try_into().unwrap());
        for idx in 0..member_len as usize {
            let offset = MEMBER_LEN_OFFSET + 2 + idx * 20;
            if &pub_key_hash == &input_data[offset..offset + 20] {
                return Ok(());
            }
        }
    }
    debug!("charge pubkey not match");
    Err(Error::InvalidSignature)
}
