use curve25519_dalek::ristretto::{RistrettoPoint};
use sha2::{Sha512, Digest};
use curve25519_dalek::scalar::Scalar;
use rug::{
    Integer,
    integer::Order
};
use std::marker::{Send, Sync};

use crate::arithm::*;
use crate::elgamal::*;
use crate::group::*;
use crate::shuffler::{YChallengeInput, TValues};

pub trait HashBytes {
    fn get_bytes(&self) -> Vec<u8>;
}

pub trait HashTo<T>: Send + Sync {
    fn hash_to(&self, bytes: &[u8]) -> T;
}

pub struct RugHasher(pub Integer);
pub struct RistrettoHasher;

impl HashTo<Scalar> for RistrettoHasher {
    fn hash_to(&self, bytes: &[u8]) -> Scalar {
        let mut hasher = Sha512::new();
        hasher.update(bytes);

        Scalar::from_hash(hasher)
    }
}

impl HashTo<Integer> for RugHasher {
    
    fn hash_to(&self, bytes: &[u8]) -> Integer {
        let mut hasher = Sha512::new();
        hasher.update(bytes);
        let hashed = hasher.finalize();

        let (_, rem) = Integer::from_digits(&hashed, Order::Lsf)
            .div_rem(self.0.clone());

        rem
    }
}

impl<E: Element + HashBytes> HashBytes for Ciphertext<E> {
    fn get_bytes(&self) -> Vec<u8> {
        let mut ret = self.a.get_bytes();
        ret.extend_from_slice(&self.b.get_bytes());

        ret
    }
}

impl HashBytes for RistrettoPoint {
    fn get_bytes(&self) -> Vec<u8> {
        self.compress().to_bytes().to_vec()
    }
}

impl HashBytes for Scalar {
    fn get_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl HashBytes for Integer {
    fn get_bytes(&self) -> Vec<u8> {
        self.to_digits::<u8>(Order::LsfLe)
    }
}

// https://stackoverflow.com/questions/39675949/is-there-a-trait-supplying-iter
fn concat_bytes_iter<'a, H: 'a + HashBytes, I: IntoIterator<Item = &'a H>>(cs: I) -> Vec<u8> {
    cs.into_iter()
    .map(|x| x.get_bytes())
    .fold(vec![], |mut a, b| {
        a.extend(b);
        a
    })
}

fn concat_bytes<T: HashBytes>(cs: &Vec<T>) -> Vec<u8> {
    concat_bytes_iter(cs)
}

pub fn shuffle_proof_us<E: Element>(es: &Vec<Ciphertext<E>>, e_primes: &Vec<Ciphertext<E>>, 
    cs: &Vec<E>, exp_hasher: &dyn HashTo<E::Exp>, n: usize) -> Vec<E::Exp> {
    
    let mut prefix_vector = concat_bytes(es);
    prefix_vector.extend(concat_bytes(e_primes));
    prefix_vector.extend(concat_bytes(cs));
    let prefix = prefix_vector.as_slice();
    let mut ret = Vec::with_capacity(n);

    for i in 0..n {
        let next_bytes: Vec<u8> = [
            prefix, 
            i.to_le_bytes().to_vec().as_slice()
        ].concat();    
        
        let u: E::Exp = exp_hasher.hash_to(&next_bytes);
        ret.push(u);
    }
    
    ret
}

pub fn shuffle_proof_challenge<E: Element, G: Group<E>>(y: &YChallengeInput<E, G>, 
    t: &TValues<E>, exp_hasher: &dyn HashTo<E::Exp>) -> E::Exp {

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

    exp_hasher.hash_to(&bytes)
}

pub fn schnorr_proof_challenge<E: Element>(g: &E, public: &E, 
    commitment: &E, exp_hasher: &dyn HashTo<E::Exp>) -> E::Exp {
    let values = [g, public, commitment].to_vec();

    let bytes = concat_bytes_iter(values);
    exp_hasher.hash_to(&bytes)
}

pub fn cp_proof_challenge<E: Element>(g1: &E, g2: &E, public1: &E, public2: &E, 
    commitment1: &E, commitment2: &E, exp_hasher: &dyn HashTo<E::Exp>) -> E::Exp {
    let values = [g1, g2, public1, public2, commitment1, commitment2].to_vec();
    
    let bytes = concat_bytes_iter(values);
    exp_hasher.hash_to(&bytes)
}

pub fn hash<T: HashBytes>(data: T) -> Vec<u8> {
    let bytes = data.get_bytes();
    let mut hasher = Sha512::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}


#[cfg(test)]
mod tests {  
    // use hex_literal::hex;
    use sha2::{Sha512, Digest};
    use rand_core::{RngCore, OsRng};
    use rug::{
        Integer,
        integer::Order
    };
    
    #[test]
    fn test_sha512() {
        
        // create a Sha256 object
        let mut hasher = Sha512::new();

        // write input message
        hasher.update(b"hello world");

        // read hash digest and consume hasher
        let mut result = [0u8;64];
        let bytes = hasher.finalize();
        result.copy_from_slice(bytes.as_slice());
    }

    #[test]
    fn test_rug_endian() {
        
        let mut csprng = OsRng;
        let value = csprng.next_u64();
        let i = Integer::from(value);

        let b1 = value.to_le_bytes().to_vec();
        let b2 = i.to_digits::<u8>(Order::LsfLe);

        assert_eq!(b1, b2);
    }

}
