use curve25519_dalek::ristretto::{RistrettoPoint};
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

pub struct RugHasher;
pub struct RistrettoHasher;

impl ExpFromHash<Scalar> for RistrettoHasher {
    fn hash_to_exp(&self, bytes: &[u8]) -> Scalar {
        let mut hasher = Sha512::new();
        hasher.update(bytes);

        Scalar::from_hash(hasher)
    }
}

const Q_STR: &str = "5bf0a8b1457695355fb8ac404e7a79e3b1738b079c5a6d2b53c26c8228c867f799273b9c49367df2fa5fc6c6c618ebb1ed0364055d88c2f5a7be3dababfacac24867ea3ebe0cdda10ac6caaa7bda35e76aae26bcfeaf926b309e18e1c1cd16efc54d13b5e7dfd0e43be2b1426d5bce6a6159949e9074f2f5781563056649f6c3a21152976591c7f772d5b56ec1afe8d03a9e8547bc729be95caddbcec6e57632160f4f91dc14dae13c05f9c39befc5d98068099a50685ec322e5fd39d30b07ff1c9e2465dde5030787fc763698df5ae6776bf9785d84400b8b1de306fa2d07658de6944d8365dff510d68470c23f9fb9bc6ab676ca3206b77869e9bdf34e8031";

impl ExpFromHash<Integer> for RugHasher {
    
    

    fn hash_to_exp(&self, bytes: &[u8]) -> Integer {
        let mut hasher = Sha512::new();
        hasher.update(bytes);
        let hashed = hasher.finalize();
        let q = Integer::from_str_radix(Q_STR, 16).unwrap();


        let (_, rem) = Integer::from_digits(&hashed, Order::Lsf).div_rem(q);

        rem
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
    cs: &Vec<E>, exp_hasher: &dyn ExpFromHash<E::Exp>, n: usize) -> Vec<E::Exp> {
    
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
        
        let u: E::Exp = exp_hasher.hash_to_exp(&hasher.finalize());
        ret.push(u);
    }
    
    ret
}

pub fn shuffle_proof_challenge<E: Element + ByteSource>(y: &YChallengeInput<E>, 
    t: &TChallengeInput<E>, exp_hasher: &dyn ExpFromHash<E::Exp>) -> E::Exp {

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

    let u: E::Exp = exp_hasher.hash_to_exp(&hasher.finalize());
    u
}