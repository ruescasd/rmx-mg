use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::arithm::*;
use crate::group::*;

#[derive(Serialize, Deserialize, Clone)]
pub struct Ciphertext<E: Element> {
    pub a: E,
    pub b: E
}

#[derive(Serialize, Deserialize)]
pub struct PublicKey<E: Element, G: Group<E, T>, T: RngCore + CryptoRng> {
    pub value: E,
    pub group: G,
    pub phantom: std::marker::PhantomData<T>
}

impl<E: Element, G: Group<E, T>, T: RngCore + CryptoRng> PublicKey<E, G, T> {
    pub fn encrypt(&self, plaintext: E, rng: T) -> Ciphertext<E> {
        
        let randomness = self.group.rnd_exp(rng);
        Ciphertext {
            a: plaintext.mul(&self.value.mod_pow(&randomness, &self.group.modulus()))
                .modulo(&self.group.modulus()),
            b: self.group.generator().mod_pow(&randomness, &self.group.modulus())
        }
    }
    pub fn from(pk_value: &E, group: &G) -> PublicKey<E, G, T> {
        PublicKey {
            value: pk_value.clone(),
            group: group.clone(),
            phantom: std::marker::PhantomData
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct PrivateKey<E: Element, G: Group<E, T>, T: RngCore + CryptoRng, > {
    pub value: E::Exp,
    pub public_value: E,
    pub group: G,
    phantom: std::marker::PhantomData<T>
}

impl<E: Element, G: Group<E, T>, T: RngCore + CryptoRng> PrivateKey<E, G, T> {
    pub fn decrypt(&self, c: &Ciphertext<E>) -> E {
        let modulus = &self.group.modulus();
        
        c.a.div(&c.b.mod_pow(&self.value, modulus), modulus)
            .modulo(modulus)
    }
    pub fn decrypt_and_prove(&self, c: &Ciphertext<E>, rng: T) -> (E, ChaumPedersen<E>) {
        let modulus = &self.group.modulus();
        
        let dec_factor = &c.b.mod_pow(&self.value, modulus);

        let proof = self.group.cp_prove(&self.value, &self.public_value, 
            dec_factor, &self.group.generator(), &c.b, rng);
        
        let decrypted = c.a.div(dec_factor, modulus)
            .modulo(modulus);

        (decrypted, proof)
    }
    pub fn decryption_factor(&self, c: &Ciphertext<E>) -> E {
        let modulus = &self.group.modulus();

        c.b.mod_pow(&self.value, modulus)
    }
    pub fn from(secret: &E::Exp, group: &G) -> PrivateKey<E, G, T> {
        let public_value = group.generator().mod_pow(&secret, &group.modulus());
        PrivateKey {
            value: secret.clone(),
            group: group.clone(),
            public_value: public_value,
            phantom: std::marker::PhantomData
        }
    }
}