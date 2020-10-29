use rand_core::{CryptoRng, RngCore};

use serde::{Deserialize, Serialize};

use crate::hashing::{HashBytes, HashTo, 
    schnorr_proof_challenge,
    cp_proof_challenge};

pub trait Element: HashBytes + Clone {
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

pub trait Group<E: Element, T: RngCore + CryptoRng> {
    
    fn generator(&self) -> E;
    fn rnd(&self, rng: T) -> E;
    fn modulus(&self) -> E;
    fn rnd_exp(&self, rng: T) -> E::Exp;
    fn exp_modulus(&self) -> E::Exp;
    fn gen_key(&self, rng: T) -> Box<dyn PrivateK<E, T>>;
    fn pk_from_value(&self, value: E) -> Box<dyn PublicK<E, T>>;
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

pub struct Keym<E: Element, T: RngCore + CryptoRng> {
    key: Box<PrivateK<E, T>>
}

impl<E: Element, T: RngCore + CryptoRng> Keym<E, T> {
    pub fn gen(group: &dyn Group<E, T>, rng: T) -> Keym<E, T> {
        Keym {
            key: group.gen_key(rng)
        }
    }
    pub fn from_sk(key: Box<PrivateK<E, T>>) -> Keym<E, T> {
        Keym {
            key: key
        }
    }
    pub fn share(&self, rng: T) -> (Box<dyn PublicK<E, T>>, Schnorr<E>) {
        let sk = &self.key;
        let group = sk.group();
        let pk = self.key.get_public_key();

        let proof = group.schnorr_prove(sk.value(), pk.value(), &group.generator(), rng);

        (pk, proof)

    }
    
    pub fn decryption_factor(&self, c: &Ciphertext<E>, rng: T) -> (E, ChaumPedersen<E>) {
        let sk = &self.key;
        let group = sk.group();
        let pk = self.key.get_public_key();
        let dec_factor = self.key.decryption_factor(c);

        let proof = group.cp_prove(sk.value(), pk.value(), &dec_factor, 
            &group.generator(), &c.b, rng);

        
        (dec_factor, proof)
    }

    pub fn combine(&self, other: Vec<Box<PublicK<E, T>>>) -> Box<PublicK<E, T>> {
        let sk = &self.key;
        let group = sk.group();
        let pk = self.key.get_public_key();

        let mut acc: E = pk.value().clone();
        for i in 0..other.len() {
            acc = acc.mul(&other[i].value()).modulo(&group.modulus());
        }

        group.pk_from_value(acc)
    }
}

/* impl<E: Element, T: RngCore + CryptoRng> Keymaker<E, T> for Keym<E, T> {
    fn key(&self) -> Box<PrivateK<E, T>> {
        self.key
    }
}*/
/*
pub trait Keymaker<E: Element, T: RngCore + CryptoRng> {
    fn key(&self) -> Box<PrivateK<E, T>>;
    fn share(&self, rng: T) -> (Box<dyn PublicK<E, T>>, Schnorr<E>) {
        let sk = self.key();
        let group = sk.group();
        let pk = self.key().get_public_key();

        let proof = group.schnorr_prove(sk.value(), pk.value(), &group.generator(), rng);

        (pk, proof)

    }
    
    fn decryption_factor(&self, c: &Ciphertext<E>, rng: T) -> E {
        let sk = self.key();
        let group = sk.group();
        let pk = self.key().get_public_key();
        let dec_factor = self.key().decryption_factor(c);

        let proof = group.cp_prove(sk.value(), pk.value(), &dec_factor, 
            &group.generator(), &c.b, rng);

        
        dec_factor
    }

}*/