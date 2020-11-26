use crate::arithm::*;
use crate::group::*;
use crate::elgamal::*;
use crate::rng::Rng;
use rayon::prelude::*;

pub struct Keymaker<E: Element, G: Group<E>> {
    sk: PrivateKey<E, G>,
    pk: PublicKey<E, G>
}

impl<E: Element, G: Group<E>> Keymaker<E, G> {
    
    pub fn gen<T: Rng>(group: &G, rng: T) -> Keymaker<E, G> {
        let sk = group.gen_key(rng);
        let pk = PublicKey::from(&sk.public_value.clone(), group);
        
        Keymaker {
            sk: sk,
            pk: pk
        }
    }
    
    pub fn share<T: Rng>(&self, rng: T) -> (PublicKey<E, G>, Schnorr<E>) {
        let group = &self.sk.group;
        let pk = group.pk_from_value(self.pk.value.clone());

        let proof = group.schnorr_prove(&self.sk.value, &pk.value, &group.generator(), rng);

        (pk, proof)

    }
    
    pub fn decryption_factor<T: Rng>(&self, c: &Ciphertext<E>, rng: T) -> (E, ChaumPedersen<E>) {
        let group = &self.sk.group;
        let dec_factor = self.sk.decryption_factor(c);

        let proof = group.cp_prove(&self.sk.value, &self.pk.value, &dec_factor, 
            &group.generator(), &c.b, rng);

        
        (dec_factor, proof)
    }

    pub fn decryption_factor_many<T: Rng + Copy>(&self, cs: &Vec<Ciphertext<E>>, rng: T) -> 
        (Vec<E>, Vec<ChaumPedersen<E>>) {
        
            let decs_proofs: (Vec<E>, Vec<ChaumPedersen<E>>) = cs.par_iter().map(|c| {
            self.decryption_factor(c, rng)
        }).unzip();
        
        decs_proofs
    }

    pub fn combine_pks(group: &G, pks: Vec<PublicKey<E, G>>) -> PublicKey<E, G> {
        let mut acc: E = pks[0].value.clone();
        for i in 1..pks.len() {
            acc = acc.mul(&pks[i].value).modulo(&group.modulus());
        }

        group.pk_from_value(acc)
    }

    pub fn joint_dec(group: &G, decs: Vec<E>, c: &Ciphertext<E>) -> E {
        let mut acc: E = decs[0].clone();
        for i in 1..decs.len() {
            acc = acc.mul(&decs[i]).modulo(&group.modulus());
        }

        c.a.div(&acc, &group.modulus()).modulo(&group.modulus())
    }

    pub fn joint_dec_many(group: &G, decs: &Vec<Vec<E>>, cs: &Vec<Ciphertext<E>>) -> Vec<E> {
        let modulus = group.modulus();
        let decrypted: Vec<E> = cs.par_iter().enumerate().map(|(i, c)| {
            let mut acc: E = decs[0][i].clone();
            for j in 1..decs.len() {
                acc = acc.mul(&decs[j][i]).modulo(&modulus);
            }
            c.a.div(&acc, &modulus).modulo(&modulus)

        }).collect();

        decrypted
    }

    // FIXME parallel
    pub fn verify_decryption_factors(group: &G, pk_value: &E, ciphertexts: &Vec<Ciphertext<E>>, 
        decs: &Vec<E>, proofs: &Vec<ChaumPedersen<E>>) -> bool {
        
        assert_eq!(decs.len(), proofs.len());
        assert_eq!(decs.len(), ciphertexts.len());
        let generator = group.generator();
        let bools: Vec<bool> = (0..decs.len()).into_par_iter().map(|i| {
            group.cp_verify(pk_value, &decs[i], &generator, &ciphertexts[i].b, &proofs[i])
        }).collect();

        !bools.contains(&false)
    }
}