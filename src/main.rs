use rand::Rng;
use rand_core::{CryptoRng, OsRng, RngCore};
use rug::{
    rand::{RandGen, RandState},
    Integer,
};

use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_POINT};

mod elgamal;

use elgamal::*;

fn main() {
    let csprng = OsRng;
    let rg = RistrettoGroup;
    
    let sk = PrivateKey::random(&rg, csprng);
    let pk = PublicKey::from(&sk);
    
    let text = "16 byte message!";
    let plaintext = rg.encode(to_u8_16(text.as_bytes().to_vec()));
    
    let c = pk.encrypt(plaintext, csprng);    
    let d = sk.decrypt(c);
    
    let recovered = String::from_utf8(rg.decode(d).to_vec());
    assert_eq!(text, recovered.unwrap());
}

fn gen_permutation(size: usize) -> Vec<usize> {
    let mut ret = Vec::with_capacity(size);
    let mut rng = rand::thread_rng();

    let mut ordered: Vec<usize> = (0..size).collect();

    for i in 0..size {
        let k = rng.gen_range(i, size);
        let j = ordered[k];
        ordered[k] = ordered[i];
        ret.push(j);
    }

    return ret;
}

/*
fn gen_shuffle<E: Element>(ciphertexts: &Vec<Ciphertext<E>>, pk: &PublicKey<E, OsRng>) -> (Vec<Ciphertext<E>>, Vec<E::Exp>, Vec<usize>) {
    let mut csprng = OsRng;
    let perm: Vec<usize> = gen_permutation(ciphertexts.len());

    let (es, rs): (Vec<Ciphertext<E>>, Vec<E::Exp>) = ciphertexts.iter().map(|c| {
            // let r = Scalar::random(&mut csprng);
            let r = pk.group.rnd_exp(csprng);
            // let a = c.a + (r * pk.0);
            // let b = c.b + (r * RISTRETTO_BASEPOINT_POINT);
            let a = c.a.mult(&pk.value.mod_pow(&r, &pk.group.modulus()));
            let b = c.b.mult(&pk.group.generator().mod_pow(&r, &pk.group.modulus()));
            let c_ = Ciphertext {
                a, b
            };
            (c_, r)
        }
    ).unzip();

    let e_primes: Vec<Ciphertext<E>> = perm.iter().map( |&i| es[i]).collect();
    
    (e_primes, rs, perm)
}
*/