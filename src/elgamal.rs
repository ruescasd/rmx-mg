use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::arithm::*;
use crate::group::*;

#[derive(Serialize, Deserialize, Clone)]
pub struct Ciphertext<E: Element> {
    pub a: E,
    pub b: E
}

pub trait PrivateK<E: Element, T: RngCore + CryptoRng> {
    fn decrypt(&self, c: &Ciphertext<E>) -> E {
        let modulus = &self.group().modulus();
        
        c.a.div(&c.b.mod_pow(&self.value(), modulus), modulus)
            .modulo(modulus)
    }
    fn decrypt_and_prove(&self, c: &Ciphertext<E>, rng: T) -> (E, ChaumPedersen<E>) {
        let modulus = &self.group().modulus();
        let pk = self.get_public_key().value().clone();
        let group = self.group();
        let dec_factor = &c.b.mod_pow(&self.value(), modulus);

        let proof = group.cp_prove(self.value(), &pk, dec_factor, &group.generator(), &c.b, rng);
        
        let decrypted = c.a.div(dec_factor, modulus)
            .modulo(modulus);

        (decrypted, proof)
    }
    fn decryption_factor(&self, c: &Ciphertext<E>) -> E {
        let modulus = &self.group().modulus();

        c.b.mod_pow(&self.value(), modulus)
    }
    fn value(&self) -> &E::Exp;
    fn group(&self) -> &dyn Group<E, T>;
    fn get_public_key(&self) -> Box<dyn PublicK<E, T>>;
}

pub trait PublicK<E: Element, T: RngCore + CryptoRng> {
    fn encrypt(&self, plaintext: E, rng: T) -> Ciphertext<E> {
        let group = self.group();
        let randomness = group.rnd_exp(rng);
        Ciphertext {
            a: plaintext.mul(&self.value().mod_pow(&randomness, &group.modulus()))
                .modulo(&group.modulus()),
            b: group.generator().mod_pow(&randomness, &group.modulus())
        }
    }
    fn value(&self) -> &E;
    fn group(&self) -> &dyn Group<E, T>;
}