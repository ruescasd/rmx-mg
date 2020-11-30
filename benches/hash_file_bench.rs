use criterion::{criterion_group, criterion_main, Criterion, SamplingMode, BenchmarkId};
use std::{
    fs::File,
    io::{self, BufRead, BufReader, Read, Write},
};
use sha2::{Sha512, Digest};
use rmxmg::util;
use rmxmg::ristretto_b::*;
use rmxmg::rug_b::*;
use rmxmg::group::*;

fn create_file() {
    // 1M = 62M
    let group = RistrettoGroup;
    let es = util::random_ristretto_ballots(1000000, &group).ciphertexts;
    // 100k = 100M
    // let group = RugGroup::default();
    // let es = util::random_rug_ballots(100000, &group).ciphertexts;
    let bytes = bincode::serialize(&es).unwrap();
    let mut file = File::create("/tmp/big_file2").unwrap();
    
    file.write_all(&bytes).unwrap();
}

fn hash_file() {
    const path: &'static str = "/tmp/big_file2";
    let file = File::open(path).unwrap();
    let mut reader = BufReader::with_capacity(4096 * 512, file);
    // create a Sha256 object
    let mut hasher = Sha512::new();

    loop {
        let length = {
            let buffer = reader.fill_buf().unwrap();
            hasher.update(buffer);
            buffer.len()
        };
        if length == 0 {
            break;
        }
        reader.consume(length);
    }


    // read hash digest and consume hasher
    let mut result = [0u8;64];
    let bytes = hasher.finalize();
    result.copy_from_slice(bytes.as_slice());
}

fn hash_file_nobuf() {
    const path: &'static str = "/tmp/big_file";
    let mut file = File::open(path).unwrap();
    // create a Sha256 object
    let mut hasher = Sha512::new();
    let mut buffer = Vec::new();
    // read the whole file
    file.read_to_end(&mut buffer).unwrap();
    hasher.update(buffer);

    // read hash digest and consume hasher
    let mut result = [0u8;64];
    let bytes = hasher.finalize();
    result.copy_from_slice(bytes.as_slice());
}

fn criterion_benchmark(c: &mut Criterion) {
    create_file();
    let mut group = c.benchmark_group("hash_file");
    group
        .sample_size(10);
    group.bench_function("hash_file", |b| b.iter(|| hash_file()));
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);