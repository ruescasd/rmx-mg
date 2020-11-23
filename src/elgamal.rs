use serde::{Deserialize, Serialize};

use crate::arithm::*;
use crate::group::*;
use crate::rng::Rng;

#[derive(Serialize, Deserialize, Clone)]
pub struct Ciphertext<E: Element> {
    pub a: E,
    pub b: E
}

#[derive(Serialize, Deserialize)]
pub struct PublicKey<E: Element, G: Group<E>> {
    pub value: E,
    pub group: G
}

impl<E: Element, G: Group<E>> PublicKey<E, G> {
    pub fn encrypt<T: Rng>(&self, plaintext: E, rng: T) -> Ciphertext<E> {
        
        let randomness = self.group.rnd_exp(rng);
        Ciphertext {
            a: plaintext.mul(&self.value.mod_pow(&randomness, &self.group.modulus()))
                .modulo(&self.group.modulus()),
            b: self.group.generator().mod_pow(&randomness, &self.group.modulus())
        }
    }
    pub fn from(pk_value: &E, group: &G) -> PublicKey<E, G> {
        PublicKey {
            value: pk_value.clone(),
            group: group.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct PrivateKey<E: Element, G: Group<E>> {
    pub value: E::Exp,
    pub public_value: E,
    pub group: G
}

impl<E: Element, G: Group<E>> PrivateKey<E, G> {
    pub fn decrypt(&self, c: &Ciphertext<E>) -> E {
        let modulus = &self.group.modulus();
        
        c.a.div(&c.b.mod_pow(&self.value, modulus), modulus)
            .modulo(modulus)
    }
    pub fn decrypt_and_prove<T: Rng>
        (&self, c: &Ciphertext<E>, rng: T) -> (E, ChaumPedersen<E>) {
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
    pub fn from(secret: &E::Exp, group: &G) -> PrivateKey<E, G> {
        let public_value = group.generator().mod_pow(&secret, &group.modulus());
        PrivateKey {
            value: secret.clone(),
            group: group.clone(),
            public_value: public_value
        }
    }
}