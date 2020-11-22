use rand_core::{CryptoRng, RngCore};
use std::marker::{Send, Sync};

use crate::arithm::*;
use crate::hashing::*;
use crate::elgamal::*;

pub trait Group<E: Element, T: RngCore + CryptoRng>: Send + Sync + Sized + Clone {
    
    fn generator(&self) -> E;
    fn rnd(&self, rng: T) -> E;
    fn modulus(&self) -> E;
    fn rnd_exp(&self, rng: T) -> E::Exp;
    fn exp_modulus(&self) -> E::Exp;
    fn gen_key(&self, rng: T) -> PrivateKey<E, Self, T>;
    fn pk_from_value(&self, value: E) -> PublicKey<E, Self, T>;
    fn encode(&self, plaintext: E::Plaintext) -> E;
    fn decode(&self, ciphertext: E) -> E::Plaintext;
    fn exp_hasher(&self) -> Box<dyn HashTo<E::Exp>>;
    
    fn schnorr_prove(&self, secret: &E::Exp, public: &E, g: &E, rng: T) -> Schnorr<E> {
        let r = self.rnd_exp(rng);
        let commitment = g.mod_pow(&r, &self.modulus());
        let challenge: E::Exp = schnorr_proof_challenge(g, public, 
            &commitment, &*self.exp_hasher());
        let response = r.add(&challenge.mul(secret)).modulo(&self.exp_modulus());

        Schnorr {
            commitment: commitment,
            challenge: challenge,
            response: response
        }
    }
    fn schnorr_verify(&self, public: &E, g: &E, proof: &Schnorr<E>) -> bool {
        let challenge_ = schnorr_proof_challenge(g, &public, &proof.commitment, 
            &*self.exp_hasher());
        let ok1 = challenge_.eq(&proof.challenge);
        let lhs = g.mod_pow(&proof.response, &self.modulus());
        let rhs = proof.commitment.mul(&public.mod_pow(&proof.challenge, &self.modulus()))
            .modulo(&self.modulus());
        let ok2 = lhs.eq(&rhs);
        ok1 && ok2
    }

    fn cp_prove(&self, secret: &E::Exp, public1: &E, public2: &E, g1: &E, g2: &E, rng: T) -> ChaumPedersen<E> {
        let r = self.rnd_exp(rng);
        let commitment1 = g1.mod_pow(&r, &self.modulus());
        let commitment2 = g2.mod_pow(&r, &self.modulus());
        let challenge: E::Exp = cp_proof_challenge(g1, g2, public1, public2,
            &commitment1, &commitment2, &*self.exp_hasher());
        let response = r.add(&challenge.mul(secret)).modulo(&self.exp_modulus());

        ChaumPedersen {
            commitment1: commitment1,
            commitment2: commitment2,
            challenge: challenge,
            response: response
        }
    }
    
    fn cp_verify(&self, public1: &E, public2: &E, g1: &E, g2: &E, proof: &ChaumPedersen<E>) -> bool {
        let challenge_ = cp_proof_challenge(g1, g2, public1, public2,
            &proof.commitment1, &proof.commitment2, &*self.exp_hasher());
        let ok1 = challenge_.eq(&proof.challenge);
        
        let lhs1 = g1.mod_pow(&proof.response, &self.modulus());
        let rhs1 = proof.commitment1.mul(&public1.mod_pow(&proof.challenge, &self.modulus()))
            .modulo(&self.modulus());
        let lhs2 = g2.mod_pow(&proof.response, &self.modulus());
        let rhs2 = proof.commitment2.mul(&public2.mod_pow(&proof.challenge, &self.modulus()))
            .modulo(&self.modulus());
        let ok2 = lhs1.eq(&rhs1);
        let ok3 = lhs2.eq(&rhs2);
        
        ok1 && ok2 && ok3
    }
}

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Schnorr<E: Element> {
    commitment: E,
    challenge: E::Exp,
    response: E::Exp
}

#[derive(Serialize, Deserialize)]
pub struct ChaumPedersen<E: Element> {
    commitment1: E,
    commitment2: E,
    challenge: E::Exp,
    response: E::Exp
}