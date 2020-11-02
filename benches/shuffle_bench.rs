use rand::Rng;
use rand_core::{OsRng};
use rug::Integer;
use serde::{Deserialize, Serialize};

use rmxmg::arithm::*;
use rmxmg::group::*;
use rmxmg::elgamal::*;
use rmxmg::ristretto_b::*;
use rmxmg::rug_b::*;
use rmxmg::hashing;
use rmxmg::hashing::{HashBytes, HashTo};
use rmxmg::shuffle::*;
use std::time::{Instant};

use criterion::{black_box, criterion_group, criterion_main, Criterion, SamplingMode, BenchmarkId};

struct GenProofIn<'a, E: Element> {
    es: &'a Vec<Ciphertext<E>>,
    e_primes: &'a Vec<Ciphertext<E>>, 
    r_primes: &'a Vec<E::Exp>, 
    perm: &'a Vec<usize>, 
    pk: &'a dyn PublicK<E, OsRng>, 
    generators: &'a Vec<E>, 
    hasher: &'a dyn HashTo<E::Exp>
}
struct CheckProofIn<'a, E: Element> {
    proof: &'a Proof<E, E::Exp>, 
    es: &'a Vec<Ciphertext<E>>,
    e_primes: &'a Vec<Ciphertext<E>>, 
    pk: &'a dyn PublicK<E, OsRng>, 
    generators: &'a Vec<E>, 
    hasher: &'a dyn HashTo<E::Exp>
}

fn gen_proof_f<E: Element>(i: &GenProofIn<E>) -> Proof<E, E::Exp> {
    gen_proof(i.es, i.e_primes, i.r_primes, i.perm, i.pk, i.generators, i.hasher)
}
fn check_proof_f<E: Element>(i: &CheckProofIn<E>) -> bool {
    check_proof(i.proof, i.es, i.e_primes, i.pk, i.generators, i.hasher)
}
fn shuffle_f(n: usize) -> bool {
    let group = RugGroup::default();
    let exp_hasher = &*group.exp_hasher();
    let csprng = OsRng;
        
    let sk = group.gen_key_conc(csprng);
    let pk = sk.get_public_key_conc();
    
    let mut es: Vec<Ciphertext<Integer>> = Vec::with_capacity(n);

    for _ in 0..n {
        let plaintext: Integer = group.encode(group.rnd_exp(csprng));
        let c = pk.encrypt(plaintext, csprng);
        es.push(c);
    }
    let hs = generators(es.len() + 1, &group);
        
    let (e_primes, rs, perm) = gen_shuffle(&es, &pk);

    let proof = gen_proof(&es, &e_primes, &rs, &perm, &pk, &hs, exp_hasher);
        
    let ok = check_proof(&proof, &es, &e_primes, &pk, &hs, exp_hasher);

    ok
}

use std::time::Duration;

fn criterion_benchmark(c: &mut Criterion) {
    let group = RugGroup::default();
    let exp_hasher = &*group.exp_hasher();
    let csprng = OsRng;
        
    let sk = group.gen_key_conc(csprng);
    let pk = sk.get_public_key_conc();
    let n = 300;
    
    let mut es: Vec<Ciphertext<Integer>> = Vec::with_capacity(n);
    
    for _ in 0..n {
        let plaintext: Integer = group.encode(group.rnd_exp(csprng));
        let c = pk.encrypt(plaintext, csprng);
        es.push(c);
    }
        
    let hs = generators(es.len() + 1, &group);
        
    let (e_primes, rs, perm) = gen_shuffle(&es, &pk);

    let i1 = GenProofIn {
        es: &es,
        e_primes: &e_primes,
        r_primes: &rs,
        perm: &perm,
        pk: &pk,
        generators: &hs,
        hasher: exp_hasher
    };

    let proof = gen_proof(&es, &e_primes, &rs, &perm, &pk, &hs, exp_hasher);

    let i2 = CheckProofIn {
        proof: &proof,
        es: &es,
        e_primes: &e_primes,
        pk: &pk,
        generators: &hs,
        hasher: exp_hasher
    };

    
    let mut group = c.benchmark_group("shuffle");
    group
        .sample_size(10)
        .measurement_time(Duration::from_secs(60))
        .sampling_mode(SamplingMode::Flat);
    /*
    group.bench_function("gen_proof", |b| 
        b.iter(|| (gen_proof_f(black_box(&i1))))
    );
    group.bench_function("check_proof", |b| 
        b.iter(|| (check_proof_f(black_box(&i2))))
    );
    */
    for size in [200].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| shuffle_f(size));
        });
    }
    
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);