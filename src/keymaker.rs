use rand_core::{CryptoRng, RngCore};

use crate::arithm::*;
use crate::group::*;
use crate::elgamal::*;

pub struct Keymaker<E: Element, G: Group<E, T>, T: RngCore + CryptoRng> {
    sk: PrivateKey<E, G, T>,
    pk: PublicKey<E, G, T>
}

impl<E: Element, T: RngCore + CryptoRng, G: Group<E, T>> Keymaker<E, G, T> {
    
    pub fn gen(group: &G, rng: T) -> Keymaker<E, G, T> {
        let sk = group.gen_key(rng);
        let pk = PublicKey::from(&sk.public_value.clone(), group);
        
        Keymaker {
            sk: sk,
            pk: pk
        }
    }
    
    pub fn share(&self, rng: T) -> (PublicKey<E, G, T>, Schnorr<E>) {
        let group = &self.sk.group;
        let pk = group.pk_from_value(self.pk.value.clone());

        let proof = group.schnorr_prove(&self.sk.value, &pk.value, &group.generator(), rng);

        (pk, proof)

    }
    
    pub fn decryption_factor(&self, c: &Ciphertext<E>, rng: T) -> (E, ChaumPedersen<E>) {
        let group = &self.sk.group;
        let dec_factor = self.sk.decryption_factor(c);

        let proof = group.cp_prove(&self.sk.value, &self.pk.value, &dec_factor, 
            &group.generator(), &c.b, rng);

        
        (dec_factor, proof)
    }

    pub fn combine_pks(&self, other: Vec<PublicKey<E, G, T>>) -> PublicKey<E, G, T> {
        let group = &self.sk.group;

        let mut acc: E = self.pk.value.clone();
        for i in 0..other.len() {
            acc = acc.mul(&other[i].value).modulo(&group.modulus());
        }

        group.pk_from_value(acc)
    }

    pub fn joint_dec(&self, decs: Vec<E>, c: Ciphertext<E>) -> E {
        let group = &self.sk.group;
        
        let mut acc: E = decs[0].clone();
        for i in 1..decs.len() {
            acc = acc.mul(&decs[i]).modulo(&group.modulus());
        }

        c.a.div(&acc, &group.modulus()).modulo(&group.modulus())
    }
}
/* 
use crate::ristretto_b::*;
use crate::rug_b::*;
use rand_core::OsRng;
use rug::Integer;
use curve25519_dalek::ristretto::RistrettoPoint;

pub struct KeymakerRug<E: Element, G: Group<E, T>, T: RngCore + CryptoRng> {
    sk: PrivateKey<E, T>,
    pk: PublicKey<E, T>,
    phantom: std::marker::PhantomData<T>
}

impl KeymakerRug {
    pub fn gen(group: &RugGroup, rng: OsRng) -> KeymakerRug {
        let sk = group.gen_key_conc(rng);
        let pk = PublicKey::from(sk.public_value.clone(), group);
        
        KeymakerRug {
            sk: sk,
            pk: pk
        }
    }
}

impl Keymaker<Integer, OsRng> for KeymakerRug {
    fn sk(&self) -> PrivateKey<Integer, OsRng> {
        self.sk.clone()
    }
    fn pk(&self) -> PublicKey<Integer, OsRng> {
        self.pk.clone()
    }
}

pub struct KeymakerRistretto {
    sk: PrivateKeyRistretto,
    pk: PublicKeyRistretto
}

impl KeymakerRistretto {
    pub fn gen(group: &RistrettoGroup, rng: OsRng) -> KeymakerRistretto {
        let sk = group.gen_key_conc(rng);
        let pk = PublicKey::from(sk.public_value, &group);
        
        KeymakerRistretto {
            sk: sk,
            pk: pk
        }
    }
}

impl Keymaker<RistrettoPoint, OsRng> for KeymakerRistretto {
    fn sk(&self) -> Box<dyn PrivateK<RistrettoPoint, OsRng>> {
        Box::new(self.sk.clone())
    }
    fn pk(&self) -> Box<dyn PublicK<RistrettoPoint, OsRng>> {
        Box::new(self.pk.clone())
    }
}*/