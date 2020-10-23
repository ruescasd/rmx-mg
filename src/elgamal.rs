use rand_core::{CryptoRng, RngCore};

use serde::{Deserialize, Serialize};

use crate::hashing::ByteSource;

pub trait Element: ByteSource + Clone {
    type Exp: Exponent;
    type Plaintext;
    
    fn mul(&self, other: &Self) -> Self;
    fn div(&self, other: &Self, modulus: &Self) -> Self;
    fn mod_pow(&self, exp: &Self::Exp, modulus: &Self) -> Self;
    fn modulo(&self, modulus: &Self) -> Self;
    fn eq(&self, other: &Self) -> bool;
}

pub trait Exponent: Clone {
    fn add(&self, other: &Self) -> Self;
    fn sub(&self, other: &Self) -> Self;
    fn neg(&self) -> Self;
    fn mul(&self, other: &Self) -> Self;
    fn modulo(&self, modulus: &Self) -> Self;
    fn eq(&self, other: &Self) -> bool;
    
    fn add_identity() -> Self;
    fn mul_identity() -> Self;
}

pub trait Group<E: Element, T: RngCore + CryptoRng> {
    fn generator(&self) -> E;
    fn rnd(&self, rng: T) -> E;
    fn modulus(&self) -> E;
    fn rnd_exp(&self, rng: T) -> E::Exp;
    fn exp_modulus(&self) -> E::Exp;
    fn gen_key(&self, rng: T) -> Box<dyn PrivateK<E, T>>;
    fn encode(&self, plaintext: E::Plaintext) -> E;
    fn decode(&self, ciphertext: E) -> E::Plaintext;
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Ciphertext<E: Element> {
    pub a: E,
    pub b: E
}

pub struct PrivateKey<'a, E: Element, T: RngCore + CryptoRng> {
    pub value: E::Exp,
    pub group: &'a dyn Group<E, T>
}

impl<'a, E: Element, T: RngCore + CryptoRng> PrivateKey<'a, E, T> {
    pub fn random(group: &'a dyn Group<E, T>, rng: T) -> Self {
        PrivateKey {
            value: group.rnd_exp(rng), 
            group: group
        }
    }
    
    pub fn decrypt(&self, c: Ciphertext<E>) -> E {
        c.a.div(&c.b.mod_pow(&self.value, &self.group.modulus()), 
            &self.group.modulus()).modulo(&self.group.modulus())
    }
}

pub trait PrivateK<E: Element, T: RngCore + CryptoRng> {
    fn decrypt(&self, c: Ciphertext<E>) -> E;
    fn value(&self) -> &E::Exp;
    fn get_public_key(&self) -> Box<dyn PublicK<E, T>>;
}

pub trait PublicK<E: Element, T: RngCore + CryptoRng> {
    fn encrypt(&self, plaintext: E, rng: T) -> Ciphertext<E>;
    fn value(&self) -> &E;
    fn group(&self) -> &dyn Group<E, T>;
}

pub struct PublicKey<'a, E: Element, T: RngCore + CryptoRng> {
    pub value: E,
    pub group: &'a dyn Group<E, T>
}

impl<'a, E: Element, T: RngCore + CryptoRng> PublicKey<'a, E, T> {

    pub fn encrypt(&self, plaintext: E, rng: T) -> Ciphertext<E> {
        let randomness = self.group.rnd_exp(rng);
        Ciphertext {
            a: plaintext.mul(&self.value.mod_pow(&randomness, &self.group.modulus())),
            b: self.group.generator().mod_pow(&randomness, &self.group.modulus())
        }
    }
    
    pub fn from(sk: &'a PrivateKey<E, T>) -> PublicKey<'a, E, T> {
        PublicKey {
            value: sk.group.generator().mod_pow(&sk.value, &sk.group.modulus()),
            group: sk.group
        }
    }
}