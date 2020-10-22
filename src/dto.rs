use crate::elgamal::*;
use crate::elgamal::*;
use crate::rug_elgamal::*;
use crate::ristretto_elgamal::*;
use crate::hashing::{ByteSource, ExpFromHash, RugHasher, RistrettoHasher};
use rand_core::{OsRng};

use rug::{Integer};
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::scalar::Scalar;

use serde::{Deserialize, Serialize};

use crate::*;

struct ShuffleDTO {
    shuffled: Vec<Ciphertext<Integer>>
}

#[test]
fn test_serde() {
    use bincode;
    let csprng = OsRng;
    let group = RugGroup::default();

    let mut bytes = bincode::serialize(&group).unwrap();

    let sk = group.gen_key_conc(csprng);
    let pk = sk.get_public_key_conc();

    /* let sk = PrivateKeyRug {
        value: group.rnd_exp(csprng),
        group: group.clone()
    };*/
    

    let mut es: Vec<Ciphertext<Integer>> = Vec::with_capacity(10);
    
    for _ in 0..10 {
        let plaintext: Integer = group.encode(group.rnd_exp(csprng));
        let c = pk.encrypt(plaintext, csprng);
        es.push(c);
    }
    
    let hs = generators(es.len() + 1, &group);
    let (e_primes, rs, perm) = gen_shuffle(&es, &pk);
    let proof = gen_proof(&es, &e_primes, &rs, &perm, &pk, &hs, &RugHasher);
    
    bytes = bincode::serialize(&sk).unwrap();
    bytes = bincode::serialize(&pk).unwrap();
    bytes = bincode::serialize(&es).unwrap();
    bytes = bincode::serialize(&e_primes).unwrap();
    bytes = bincode::serialize(&proof).unwrap();
    
    let ok = check_proof(&proof, &es, &e_primes, &pk, &hs, &RugHasher);

    assert!(ok == true);
    
    /* let pk = sk.get_public_key_conc();

    bytes = bincode::serialize(&pk).unwrap();

    let plaintext = group.rnd_exp(csprng);
    
    let encoded = group.encode(plaintext.clone());
    let c = pk.encrypt(encoded.clone(), csprng);
    
    let mut bytes = bincode::serialize(&c).unwrap();
    let d: Ciphertext<Integer> = bincode::deserialize(&bytes).unwrap();

    assert_eq!(c.a, d.a);
    assert_eq!(c.b, d.b);*/
    // assert_eq!(enc_plaintext.points, decoded.points);
}