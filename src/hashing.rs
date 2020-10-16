use curve25519_dalek::ristretto::{RistrettoPoint};
use rand_core::{OsRng};
use sha2::{Sha512, Digest};
use curve25519_dalek::scalar::Scalar;
use rug::{
    Integer,
    integer::Order
};

use crate::elgamal::*;
use crate::{YChallengeInput, TChallengeInput};

pub trait ByteSource {
    fn get_bytes(&self) -> Vec<u8>;
}

pub trait ExpFromHash<T> {
    fn hash_to_exp(&self, bytes: &[u8]) -> T;
}

impl ExpFromHash<Scalar> for RistrettoGroup {
    fn hash_to_exp(&self, bytes: &[u8]) -> Scalar {
        let mut hasher = Sha512::new();
        hasher.update(bytes);

        Scalar::from_hash(hasher)
    }
}

impl ExpFromHash<Integer> for RugGroup {
    
    fn hash_to_exp(&self, bytes: &[u8]) -> Integer {
        let mut hasher = Sha512::new();
        hasher.update(bytes);
        let hashed = hasher.finalize();

        Integer::from_digits(&hashed, Order::Lsf)
    }
}


impl<E: Element + ByteSource> ByteSource for Ciphertext<E> {
    fn get_bytes(&self) -> Vec<u8> {
        let mut ret = self.a.get_bytes();
        ret.extend_from_slice(&self.b.get_bytes());

        ret
    }
}

impl ByteSource for RistrettoPoint {
    fn get_bytes(&self) -> Vec<u8> {
        self.compress().to_bytes().to_vec()
    }
}

impl ByteSource for Scalar {
    fn get_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl ByteSource for Integer {
    fn get_bytes(&self) -> Vec<u8> {
        self.to_digits::<u8>(Order::Lsf)
    }
}

fn test<E: Element + ByteSource>(e: E) -> Vec<u8> {
    e.get_bytes()
}


fn concat_bytes<T: ByteSource>(cs: &Vec<T>) -> Vec<u8> {
    return 
        cs.iter()
        .map(|x| x.get_bytes())
        .fold(vec![], |mut a, b| {
            a.extend(b);
            a
        });
}

pub fn shuffle_proof_us<E: Element + ByteSource>(es: &Vec<Ciphertext<E>>, e_primes: &Vec<Ciphertext<E>>, 
    cs: &Vec<E>, group: &dyn Group<E, OsRng>, n: usize) -> Vec<E::Exp> {
    
    let mut prefix_vector = concat_bytes(es);
    prefix_vector.extend(concat_bytes(e_primes));
    prefix_vector.extend(concat_bytes(cs));
    let prefix = prefix_vector.as_slice();
    let mut ret = Vec::with_capacity(n);

    for i in 0..n {
        let next_bytes: Vec<u8> = [
            prefix, 
            i.to_be_bytes().to_vec().as_slice()
        ].concat();    
        let mut hasher = Sha512::new();
        hasher.update(next_bytes);
        
        let u: E::Exp = group.hash_to_exp(&hasher.finalize());
        ret.push(u);
    }
    
    ret
}

pub fn shuffle_proof_challenge<E: Element + ByteSource>(y: &YChallengeInput<E>, 
    t: &TChallengeInput<E>, group: &dyn Group<E, OsRng>) -> E::Exp {

    let mut bytes = concat_bytes(&y.es);
    bytes.extend(concat_bytes(&y.e_primes));
    bytes.extend(concat_bytes(&y.cs));
    bytes.extend(concat_bytes(&y.c_hats));
    bytes.extend(y.pk.value.get_bytes());
    
    bytes.extend(t.t1.get_bytes());
    bytes.extend(t.t2.get_bytes());
    bytes.extend(t.t3.get_bytes());
    bytes.extend(t.t4_1.get_bytes());
    bytes.extend(t.t4_2.get_bytes());
    bytes.extend(concat_bytes(&t.t_hats));

    let mut hasher = Sha512::new();
    hasher.update(bytes);

    let u: E::Exp = group.hash_to_exp(&hasher.finalize());
    u
}