use std::{
    fs::File,
    io::{BufWriter, Read, Write},
    path::Path,
};

use blake2b_rs::Blake2bBuilder;

const BUF_SIZE: usize = 8 * 1024;
const CKB_HASH_PERSONALIZATION: &[u8] = b"ckb-default-hash";

fn main() {
    // build_static_c_lib();
    gen_code_hash();
}

// fn build_static_c_lib() {
//     cc::Build::new()
//         .file("lib.c")
//         .static_flag(true)
//         .flag("-O3")
//         .flag("-fno-builtin-printf")
//         .flag("-fno-builtin-memcmp")
//         .flag("-nostdinc")
//         .flag("-nostdlib")
//         .flag("-fvisibility=hidden")
//         .flag("-fdata-sections")
//         .flag("-ffunction-sections")
//         .include("ckb-c-stdlib")
//         .include("ckb-c-stdlib/libc")
//         .include("ckb-c-stdlib/molecule")
//         // .flag("-Wall")
//         // .flag("-Werror")
//         .flag("-Wno-unused-parameter")
//         .flag("-Wno-nonnull")
//         .define("__SHARED_LIBRARY__", None)
//         .flag("-Wno-nonnull-compare")
//         .flag("-nostartfiles")
//         .compile("dl-c-impl");
// }

fn gen_code_hash() {
    let out_path = Path::new("src").join("code_hashes.rs");
    let mut out_file = BufWriter::new(File::create(&out_path).expect("create code_hashes.rs"));

    let name = "SHARED_LIB";
    let path = "ckb-production-scripts/build/validate_signature_rsa";

    let mut buf = [0u8; BUF_SIZE];

    // build hash
    let mut blake2b = Blake2bBuilder::new(32)
        .personal(CKB_HASH_PERSONALIZATION)
        .build();
    let mut fd = File::open(&path).expect("open file");
    loop {
        let read_bytes = fd.read(&mut buf).expect("read file");
        if read_bytes > 0 {
            blake2b.update(&buf[..read_bytes]);
        } else {
            break;
        }
    }

    let mut hash = [0u8; 32];
    blake2b.finalize(&mut hash);

    write!(
        &mut out_file,
        "pub const {}: [u8; 32] = {:?};\n",
        format!("CODE_HASH_{}", name.to_uppercase().replace("-", "_")),
        hash
    )
    .expect("write to code_hashes.rs");
}
