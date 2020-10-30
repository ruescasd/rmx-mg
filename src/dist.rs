use rand_core::{CryptoRng, RngCore};

use crate::arithm::*;
use crate::group::*;
use crate::elgamal::*;

pub struct Keym<E: Element, T: RngCore + CryptoRng> {
    sk: Box<dyn PrivateK<E, T>>,
    pk: Box<dyn PublicK<E, T>>
}

impl<E: Element, T: RngCore + CryptoRng> Keym<E, T> {
    pub fn gen(group: &dyn Group<E, T>, rng: T) -> Keym<E, T> {
        let sk = group.gen_key(rng);
        let pk = sk.get_public_key();
        Keym {
            sk: sk,
            pk: pk
        }
    }
    
    pub fn share(&self, rng: T) -> (Box<dyn PublicK<E, T>>, Schnorr<E>) {
        let group = self.sk.group();
        let pk = group.pk_from_value(self.pk.value().clone());

        let proof = group.schnorr_prove(self.sk.value(), pk.value(), &group.generator(), rng);

        (pk, proof)

    }
    
    pub fn decryption_factor(&self, c: &Ciphertext<E>, rng: T) -> (E, ChaumPedersen<E>) {
        let group = self.sk.group();
        let dec_factor = self.sk.decryption_factor(c);

        let proof = group.cp_prove(self.sk.value(), self.pk.value(), &dec_factor, 
            &group.generator(), &c.b, rng);

        
        (dec_factor, proof)
    }

    pub fn combine_pks(&self, other: Vec<Box<dyn PublicK<E, T>>>) -> Box<dyn PublicK<E, T>> {
        let group = self.sk.group();

        let mut acc: E = self.pk.value().clone();
        for i in 0..other.len() {
            acc = acc.mul(&other[i].value()).modulo(&group.modulus());
        }

        group.pk_from_value(acc)
    }

    pub fn joint_dec(&self, decs: Vec<E>, c: Ciphertext<E>) -> E {
        let group = self.sk.group();
        
        let mut acc: E = decs[0].clone();
        for i in 1..decs.len() {
            acc = acc.mul(&decs[i]).modulo(&group.modulus());
        }

        c.a.div(&acc, &group.modulus()).modulo(&group.modulus())
    }
}