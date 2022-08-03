use super::*;
use ckb_hash::{blake2b_256, new_blake2b};
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_error::assert_error_eq;
use ckb_testtool::ckb_script::ScriptError;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::context::Context;
use rsa::{hash::Hash, padding::PaddingScheme, PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_CYCLES: u64 = 10_000_000;

// error numbers
const RSA_BIN: &[u8] = include_bytes!("../../contracts/operator-script/validate_signature_rsa");

struct RoomInfo {
    current_count: u64,
    message_price: u64,
    timelock: u64,
    // Host's RSA public key blake160 hash
    host_pubkey: RsaPublicKey,
    // Host's lock script hash, for receiving the charge capacity
    host_lock_hash: [u8; 32],
    // Owner's RSA public key blake160 hash
    owner_pubkey: RsaPublicKey,
    members_pubkey_hash: Vec<RsaPublicKey>,
}

fn rsa_pubkey_data(pubkey: &RsaPublicKey) -> Vec<u8> {
    let mut e = pubkey.e().to_bytes_le();
    let mut n = pubkey.n().to_bytes_le();
    while e.len() < 4 {
        e.push(0);
    }
    while n.len() < pubkey.size() {
        n.push(0)
    }
    e.extend(n);
    e
}

fn rsa_pubkey_blake160(pubkey: &RsaPublicKey) -> [u8; 20] {
    let hash = blake2b_256(&rsa_pubkey_data(pubkey));
    let mut blake160 = [0u8; 20];
    blake160.copy_from_slice(&hash[0..20]);
    blake160
}

impl RoomInfo {
    fn to_cell_data(&self) -> Vec<u8> {
        let data_len = 8 + 8 + 8 + 20 + 32 + 20 + 2 + 20 * self.members_pubkey_hash.len();
        let mut data = vec![0u8; data_len];
        data[0..8].copy_from_slice(&self.current_count.to_le_bytes()[..]);
        data[8..16].copy_from_slice(&self.message_price.to_le_bytes()[..]);
        data[16..24].copy_from_slice(&self.timelock.to_le_bytes()[..]);
        data[24..44].copy_from_slice(&rsa_pubkey_blake160(&self.host_pubkey)[..]);
        data[44..76].copy_from_slice(&self.host_lock_hash[..]);
        data[76..96].copy_from_slice(&rsa_pubkey_blake160(&self.owner_pubkey)[..]);
        data[96..98].copy_from_slice(&(self.members_pubkey_hash.len() as u16).to_le_bytes()[..]);
        let mut offset = 98;
        for pubkey in &self.members_pubkey_hash {
            data[offset..offset + 20].copy_from_slice(&rsa_pubkey_blake160(pubkey)[..]);
            offset += 20;
        }
        data
    }
}

fn gen_keypair(bit_size: usize) -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, bit_size).expect("generate a key");
    let pub_key = priv_key.to_public_key();
    (priv_key, pub_key)
}

#[repr(u32)]
enum Action {
    Charge = 1,
    ExtendTimelock = 2,
}

fn build_witness(privkey: &RsaPrivateKey, action: Action, message: &[u8]) -> Vec<u8> {
    let pubkey = privkey.to_public_key();
    let bit_size = pubkey.size() * 8;
    let key_size: u8 = match bit_size {
        1024 => 1,
        2048 => 2,
        4098 => 3,
        _ => {
            panic!("invalid bit size: {}", bit_size);
        }
    };
    let sign_padding = PaddingScheme::PKCS1v15Sign {
        hash: Some(Hash::SHA2_256),
    };
    let mut hasher = Sha256::new();
    hasher.update(&message[..]);
    let digest = hasher.finalize();
    let signature = privkey.sign(sign_padding, digest.as_slice()).unwrap();
    assert_eq!(signature.len(), pubkey.size());
    let mut witness = vec![0u8; 4 + pubkey.size() * 2 + 8];
    witness[0..4].copy_from_slice(&(action as u32).to_le_bytes()[..]);
    // use rsa to verify signature
    witness[4] = 1;
    // key size (enum)
    witness[5] = key_size;
    // pkcs#1.5
    witness[6] = 0;
    // sha2_256
    witness[7] = 6;

    let pubkey_data = rsa_pubkey_data(&pubkey);
    // pubkey.E
    witness[8..12].copy_from_slice(&pubkey_data[0..4]);
    // pubkey.N
    witness[12..12 + pubkey.size()].copy_from_slice(&pubkey_data[4..]);
    // signature
    witness[12 + pubkey.size()..].copy_from_slice(&signature);
    witness
}

#[test]
fn test_create_success() {
    // deploy contract
    let mut context = Context::default();
    let type_bin: Bytes = Loader::default().load_binary("operator-script");
    let type_out_point = context.deploy_cell(type_bin);
    let lock_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let rsa_out_point = context.deploy_cell(Bytes::from(RSA_BIN.to_vec()));
    let rsa_dep = CellDep::new_builder().out_point(rsa_out_point).build();

    let host_pubkey = gen_keypair(2048).1;
    let owner_pubkey = gen_keypair(2048).1;
    let member1_pubkey = gen_keypair(2048).1;
    let member2_pubkey = gen_keypair(2048).1;
    let timelock = {
        let start = SystemTime::now();
        let mut since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        // one hour later;
        since_the_epoch += Duration::from_secs(3600);
        since_the_epoch.as_secs() * 1000
    };
    let room_info = RoomInfo {
        current_count: 0,
        message_price: 1000,
        timelock,
        host_pubkey,
        host_lock_hash: [1u8; 32],
        owner_pubkey,
        members_pubkey_hash: vec![member1_pubkey, member2_pubkey],
    };
    let cell_data = room_info.to_cell_data();

    // prepare scripts
    let lock_script = context
        .build_script(&lock_out_point, Bytes::default())
        .expect("lock script");
    let lock_script_dep = CellDep::new_builder().out_point(lock_out_point).build();

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let type_id = {
        let mut blake2b = new_blake2b();
        blake2b.update(input.as_slice());
        blake2b.update(&0u64.to_le_bytes());
        let mut ret = vec![0u8; 32];
        blake2b.finalize(&mut ret);
        Bytes::from(ret)
    };
    let type_script = context
        .build_script(&type_out_point, type_id)
        .expect("type script");
    let type_script_dep = CellDep::new_builder().out_point(type_out_point).build();

    let outputs = vec![
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .type_(Some(type_script).pack())
            .lock(lock_script.clone())
            .build(),
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script)
            .build(),
    ];

    let outputs_data = vec![Bytes::from(cell_data), Bytes::new()];

    // build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(type_script_dep)
        .cell_dep(lock_script_dep)
        .cell_dep(rsa_dep)
        .build();
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_charge_by_signature() {
    // deploy contract
    let mut context = Context::default();
    let type_bin: Bytes = Loader::default().load_binary("operator-script");
    let type_out_point = context.deploy_cell(type_bin);
    let lock_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let rsa_out_point = context.deploy_cell(Bytes::from(RSA_BIN.to_vec()));
    let rsa_dep = CellDep::new_builder().out_point(rsa_out_point).build();

    let type_id = Bytes::from(vec![3u8; 32]);
    let type_script = context
        .build_script(&type_out_point, type_id.clone())
        .expect("type script");
    let type_script_dep = CellDep::new_builder().out_point(type_out_point).build();

    let host_lock_script = context
        .build_script(&lock_out_point, Bytes::from(vec![2u8; 20]))
        .expect("host lock");
    let host_lock_hash = blake2b_256(host_lock_script.as_slice());

    let bit_size: usize = 2048;
    let (host_privkey, host_pubkey) = gen_keypair(bit_size);
    let (owner_privkey, owner_pubkey) = gen_keypair(bit_size);
    let (member1_privkey, member1_pubkey) = gen_keypair(bit_size);
    let (member2_privkey, member2_pubkey) = gen_keypair(bit_size);
    let timelock = {
        let start = SystemTime::now();
        let mut since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        // one hour later;
        since_the_epoch += Duration::from_secs(3600);
        since_the_epoch.as_secs() * 1000
    };
    let message_price: u64 = 100;
    let mut room_info = RoomInfo {
        current_count: 0,
        message_price,
        timelock,
        host_pubkey,
        host_lock_hash,
        owner_pubkey,
        members_pubkey_hash: vec![member1_pubkey, member2_pubkey],
    };
    let prev_cell_data = room_info.to_cell_data();
    let delta_count: u64 = 20;
    room_info.current_count += delta_count;
    let next_cell_data = room_info.to_cell_data();
    let delta_capacity = delta_count * message_price;

    // prepare scripts
    let lock_script = context
        .build_script(&lock_out_point, Bytes::default())
        .expect("lock script");
    let lock_script_dep = CellDep::new_builder().out_point(lock_out_point).build();

    // room info cell
    let input1_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(10_000u64.pack())
            .type_(Some(type_script.clone()).pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::from(prev_cell_data),
    );
    // host's cell to receiver the capacity
    let input2_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(host_lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let inputs = vec![
        CellInput::new_builder()
            .previous_output(input1_out_point)
            .build(),
        CellInput::new_builder()
            .previous_output(input2_out_point)
            .build(),
    ];

    let outputs = vec![
        CellOutput::new_builder()
            .capacity((10_000 - delta_capacity).pack())
            .type_(Some(type_script.clone()).pack())
            .lock(lock_script.clone())
            .build(),
        CellOutput::new_builder()
            .capacity((1000 + delta_capacity).pack())
            .lock(host_lock_script)
            .build(),
    ];

    let outputs_data = vec![Bytes::from(next_cell_data), Bytes::new()];

    // the message to sign
    let message = {
        let mut hasher = new_blake2b();
        hasher.update(type_id.as_ref());
        hasher.update(&delta_count.to_le_bytes()[..]);
        let mut ret = [0u8; 32];
        hasher.finalize(&mut ret);
        ret
    };
    // build transaction
    let base_tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(type_script_dep)
        .cell_dep(lock_script_dep)
        .cell_dep(rsa_dep)
        .build();

    // owner key or member's key can charge
    for privkey in [&owner_privkey, &member1_privkey, &member2_privkey] {
        let witness_data = build_witness(privkey, Action::Charge, &message[..]);
        let witness = WitnessArgs::new_builder()
            .input_type(Some(Bytes::from(witness_data)).pack())
            .build()
            .as_bytes();

        let tx = base_tx
            .as_advanced_builder()
            .witness(witness.pack())
            .build();
        let tx = context.complete_tx(tx);

        // run
        let cycles = context
            .verify_tx(&tx, MAX_CYCLES)
            .expect("pass verification");
        println!("consume cycles: {}", cycles);
    }

    // Host key can not charge
    let witness_data = build_witness(&host_privkey, Action::Charge, &message[..]);
    let witness = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(witness_data)).pack())
        .build()
        .as_bytes();
    let tx = base_tx
        .as_advanced_builder()
        .witness(witness.pack())
        .build();
    let tx = context.complete_tx(tx);
    // run
    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    assert_error_eq!(
        err,
        ScriptError::validation_failure(&type_script, 6).input_type_script(0)
    );
}
