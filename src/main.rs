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

pub struct yChallengeInput<'a, E: Element> {
    pub es: &'a Vec<Ciphertext<E>>,
    pub e_primes: &'a Vec<Ciphertext<E>>,
    pub cs: &'a Vec<E>,
    pub c_hats: &'a Vec<E>,
    pub pk: &'a PublicKey<'a, E, OsRng>
}

pub struct tChallengeInput<E: Element> {
    pub t1: E,
    pub t2: E,
    pub t3: E,
    pub t4_1: E,
    pub t4_2: E,
    pub t_hats: Vec<E>
}

pub struct Responses<E: Element> {
    s1: E::Exp,
    s2: E::Exp,
    s3: E::Exp,
    s4: E::Exp,
    s_hats: Vec<E::Exp>,
    s_primes: Vec<E::Exp>
}

pub struct Proof<E: Element> {
    t: tChallengeInput<E>,
    s: Responses<E>,
    cs: Vec<E>,
    c_hats: Vec<E>
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

use std::mem;

fn gen_shuffle<E: Element>(ciphertexts: &Vec<Ciphertext<E>>, pk: &PublicKey<E, OsRng>) -> (Vec<Ciphertext<E>>, Vec<E::Exp>, Vec<usize>) {
    let csprng = OsRng;
    let perm: Vec<usize> = gen_permutation(ciphertexts.len());

    let mut e_primes = Vec::with_capacity(ciphertexts.len());
    let mut rs = Vec::with_capacity(ciphertexts.len());

    unsafe {
        rs.set_len(ciphertexts.len());
        for i in 0..perm.len() {
            let c = &ciphertexts[perm[i]];
    
            let r = pk.group.rnd_exp(csprng);
            let a = c.a.mult(&pk.value.mod_pow(&r, &pk.group.modulus()));
            let b = c.b.mult(&pk.group.generator().mod_pow(&r, &pk.group.modulus()));
            let c_ = Ciphertext {
                a: a, 
                b: b
            };
            e_primes.push(c_);
            rs[perm[i]] = r;
        }
    }
    
    (e_primes, rs, perm)
}

fn gen_commitments<E: Element>(perm: &Vec<usize>, generators: &Vec<E>, group: &Group<E, OsRng>)  -> (Vec<E>, Vec<E::Exp>) {
    let mut csprng = OsRng;

    assert!(generators.len() == perm.len());
    
    let mut rs = Vec::with_capacity(perm.len());
    let mut cs = Vec::with_capacity(perm.len());
    
    unsafe {
        rs.set_len(perm.len());
        cs.set_len(perm.len());
    
        for i in 0..perm.len() {
            let r = group.rnd_exp(csprng);
            let c = generators[i].mult(&group.generator().mod_pow(&r, &group.modulus()));
            rs[perm[i]] = r;
            cs[perm[i]] = c;
        }
    }
    (cs, rs)
}

fn gen_commitment_chain<E: Element>(initial: &E, us: &Vec<E::Exp>, group: &Group<E, OsRng>)  -> (Vec<E>, Vec<E::Exp>) {
    let mut csprng = OsRng;
    let mut cs: Vec<E> = Vec::with_capacity(us.len());
    let mut rs: Vec<E::Exp> = Vec::with_capacity(us.len());
    
    for i in 0..us.len() {
        let r = group.rnd_exp(csprng);
        let c_temp = if i == 0 {
            initial
        } else {
            &cs[i-1]
        };
        
        let first = group.generator().mod_pow(&r, &group.modulus());
        let second = c_temp.mod_pow(&us[i], &group.modulus());
        let c = first.mult(&second);

        cs.push(c);
        rs.push(r);
    }

    (cs, rs)
}

// FIXME not kosher
fn generators<E: Element>(size: usize, group: &Group<E, OsRng>) -> Vec<E> {
    let mut csprng = OsRng;
    let mut ret: Vec<E> = Vec::with_capacity(size);
    
    for _ in 0..size {
        let g = group.rnd(csprng);
        ret.push(g);
    }

    ret
}

