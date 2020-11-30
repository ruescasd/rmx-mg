use crate::arithm::*;
use crate::group::*;
use crate::elgamal::*;
use crate::artifact::*;
use curve25519_dalek::ristretto::{RistrettoPoint};
use rug::Integer;
use rayon::prelude::*;

pub fn to_u8_30(input: Vec<u8>) -> [u8; 30] {
    assert_eq!(input.len(), 30);
    let mut bytes = [0u8; 30];
    bytes.copy_from_slice(&input);
    bytes
}

pub fn to_u8_64(input: Vec<u8>) -> [u8; 64] {
    assert_eq!(input.len(), 64);
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&input);
    bytes
}

pub fn random_ristretto_ballots<G: Group<RistrettoPoint>>(n: usize, group: &G) -> Ballots<RistrettoPoint> {
    // let mut cs = Vec::with_capacity(n);
    // for _ in 0..n {
    let cs = (0..n).into_par_iter().map(|_| {
        // cs.push(
            Ciphertext{
                a: group.rnd(),
                b: group.rnd()
            }
        // );
    }).collect();

    Ballots {
        ciphertexts: cs
    }
}

pub fn random_rug_ballots<G: Group<Integer>>(n: usize, group: &G) -> Ballots<Integer> {
    // let mut cs = Vec::with_capacity(n);
    let cs = (0..n).into_par_iter().map(|_| {
        
            Ciphertext{
                a: group.encode(group.rnd_exp()),
                b: group.encode(group.rnd_exp())
            }
        
    }).collect();

    Ballots {
        ciphertexts: cs
    }
}