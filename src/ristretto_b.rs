use serde::{Deserialize, Serialize};

use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_POINT};
use curve25519_dalek::traits::Identity;

use crate::arithm::*;
use crate::elgamal::*;
use crate::group::*;
use crate::hashing::{HashTo, RistrettoHasher};
use crate::rng::Rng;

impl Element for RistrettoPoint {
    type Exp = Scalar;
    type Plaintext = [u8; 16];

    fn mul(&self, other: &Self) -> Self {
        self + other
    }
    fn div(&self, other: &Self, _modulus: &Self) -> Self {
        self - other
    }
    fn mod_pow(&self, other: &Self::Exp, _modulus: &Self) -> Self {
        self * other
    }
    fn modulo(&self, _modulus: &Self) -> Self {
        *self
    }
    fn eq(&self, other: &RistrettoPoint) -> bool {
        self == other
    }
    fn mul_identity() -> RistrettoPoint {
        RistrettoPoint::identity()
    }
}

impl Exponent for Scalar {
    fn add(&self, other: &Scalar) -> Scalar {
        self + other
    }
    fn sub(&self, other: &Scalar) -> Scalar {
        self - other
    }
    fn neg(&self) -> Scalar {
        -self
    }
    fn mul(&self, other: &Scalar) -> Scalar {
        self * other
    }
    fn modulo(&self, _modulus: &Scalar) -> Scalar {
        *self   
    }
    fn eq(&self, other: &Scalar) -> bool {
        self == other
    }
    fn add_identity() -> Scalar {
        Scalar::zero()
    }
    fn mul_identity() -> Scalar {
        Scalar::one()
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RistrettoGroup;

impl RistrettoGroup {
    fn encode_test(&self, plaintext: [u8; 16]) -> u32 {
        let upper = [0u8; 12];
        let mut id: u32 = 0;

        for i in 0..100 {
            let id_bytes = id.to_be_bytes();
            
            let mut bytes = upper.to_vec();
            bytes.extend_from_slice(&plaintext);
            bytes.extend_from_slice(&id_bytes);
            
            let cr = CompressedRistretto::from_slice(bytes.as_slice());
            
            let result = cr.decompress();
            if result.is_some() {
                return i + 1;
            }
            
            id = id + 1;
        }

        panic!("Failed to encode {:?}", plaintext);
    }

    /* pub fn gen_key_conc(&self, rng: OsRng) -> PrivateKeyRistretto {
        let secret = self.rnd_exp(rng);
        PrivateKey::from(secret, &self.clone())
    }*/
}

impl Group<RistrettoPoint> for RistrettoGroup {
    fn generator(&self) -> RistrettoPoint {
        RISTRETTO_BASEPOINT_POINT
    }
    fn rnd<T: Rng>(&self, mut rng: T) -> RistrettoPoint {
        RistrettoPoint::random(&mut rng)
    }
    fn modulus(&self) -> RistrettoPoint {
        RistrettoPoint::default()
    }
    fn rnd_exp<T: Rng>(&self, mut rng: T) -> Scalar {
        Scalar::random(&mut rng)
    }
    fn exp_modulus(&self) -> Scalar {
        Scalar::default()
    }
    fn encode(&self, plaintext: [u8; 16]) -> RistrettoPoint {
        let upper = [0u8; 12];
        let mut id: u32 = 0;

        
        // FIXME why is p = 1/4 and not 1/8 since ristretto uses cofactor 8 curve?
        // Update: see 
        // https://github.com/hdevalence/ristretto255-data-encoding/blob/master/src/main.rs
        // https://github.com/dalek-cryptography/curve25519-dalek/issues/322
        // 
        //
        // cdf geometric distribution: 1-(1-p)^k
        // probability of sucess after 100 attempts:
        // 1-(1-1/4)^100 = 0.9999999999996792797815
        for _i in 0..100 {
            let id_bytes = id.to_be_bytes();
                        
            let mut bytes = upper.to_vec();
            bytes.extend_from_slice(&plaintext);
            bytes.extend_from_slice(&id_bytes);
            
            let cr = CompressedRistretto::from_slice(bytes.as_slice());
            
            let result = cr.decompress();
            if result.is_some() {
                return result.unwrap();
            }
            
            id = id + 1;
        }

        panic!("Failed to encode {:?}", plaintext);
    }
    fn decode(&self, element: RistrettoPoint) -> [u8; 16] {
        let compressed = element.compress();
        let slice = &compressed.as_bytes()[12..28];
        to_u8_16(slice.to_vec())
    }
    fn gen_key<T: Rng>(&self, rng: T) -> PrivateKey<RistrettoPoint, Self> {
        let secret = self.rnd_exp(rng);
        PrivateKey::from(&secret, self)
    }
    fn pk_from_value(&self, value: RistrettoPoint) -> PublicKey<RistrettoPoint, Self> {
        PublicKey::from(&value, &self.clone())
    }

    fn exp_hasher(&self) -> Box<dyn HashTo<Scalar>> {
        Box::new(RistrettoHasher)
    }
    
}

use std::convert::TryInto;

pub fn to_u8_16<T>(v: Vec<T>) -> [T; 16] {
    let boxed_slice = v.into_boxed_slice();
    let boxed_array: Box<[T; 16]> = match boxed_slice.try_into() {
        Ok(ba) => ba,
        Err(o) => panic!("Expected a Vec of length {} but it was {}", 16, o.len()),
    };
    *boxed_array
}


#[cfg(test)]
mod tests {
    extern crate textplots;
    use textplots::{utils, Chart, Plot, Shape};

    use rand_core::{OsRng, RngCore};

    use curve25519_dalek::ristretto::{RistrettoPoint};
    use curve25519_dalek::traits::Identity;

    use crate::arithm::*;
    use crate::group::*;
    use crate::keymaker::*;
    use crate::ristretto_b::*;
    use crate::shuffler::*;
    use crate::artifact::*;

    #[test]
    fn test_ristretto_elgamal() {
        let csprng = OsRng;
        let group = RistrettoGroup;
        
        let sk = group.gen_key(csprng);
        let pk = PublicKey::from(&sk.public_value, &group);
        
        let text = "16 byte message!";
        let plaintext = group.encode(to_u8_16(text.as_bytes().to_vec()));
        
        let c = pk.encrypt(plaintext, csprng);    
        let d = sk.decrypt(&c);
        
        let recovered = String::from_utf8(group.decode(d).to_vec());
        assert_eq!(text, recovered.unwrap());
    }

    #[test]
    fn test_ristretto_js_encoding() {
        
        let rg = RistrettoGroup;
        
        // since we are not encoding ristretto, this string cannot be changed
        let text = "this has to be exactly 32 bytes!";
        
        // data generated by ristretto255.js
        
        let skb: [u8;32] = [
            157, 127, 250, 139, 158,  32, 121,
            69, 255, 102, 151, 206, 199, 225,
            118, 203, 168, 220, 193, 198, 226,
            74, 167,  77, 209,  52,  70, 173,
            180, 176, 153,   9
        ];
        
        let a: [u8;32] = [
            72,  60, 143,  64,  93, 212,  68, 113,
            253,   8, 206,  72, 111,  39,  75, 156,
            189,  63, 176, 223,  97, 221,  58, 132,
                11, 209,  70, 149,  90,  73, 141,  70
        ];
            
        let b: [u8;32] = [
            182,  67, 141,   0, 95, 109,  54, 179,
            179, 226,  25, 148, 80, 160, 171,  82,
            173, 129,  68,  24, 64, 236,  36, 144,
            183, 193,  36, 180, 82, 206,  98,  41
        ];

        /* let sk_ = PrivateKeyRistretto {
            value: Scalar::from_bytes_mod_order(skb), 
            group: rg
        };*/
        let sk_ = PrivateKey::from(
            &Scalar::from_bytes_mod_order(skb), 
            &rg
        );
        let c_ = Ciphertext {
            a: CompressedRistretto(a).decompress().unwrap(),
            b: CompressedRistretto(b).decompress().unwrap()
        };
        
        let d_: RistrettoPoint = sk_.decrypt(&c_);
        let recovered_ = String::from_utf8(d_.compress().as_bytes().to_vec());
        
        assert_eq!(text, recovered_.unwrap());
    }

    #[test]
    fn test_ristretto_prob_encoding() {
        let mut csprng = OsRng;
        let mut bytes = [00u8; 16];
        let group = RistrettoGroup;

        let iterations = 10000;
        println!("test_r_encoding: running {} encode iterations..", iterations);

        let v: Vec<(f32, f32)> = (0..iterations).map(|i| {
            csprng.fill_bytes(&mut bytes);
            let fixed = to_u8_16(bytes.to_vec());
        
            (i as f32, group.encode_test(fixed) as f32)
        }).collect();

        let size: f32 = v.len() as f32;
        let values: Vec<u32> = v.iter().map(|x| x.1 as u32).collect();
        let sum: f32 = v.iter().map(|x| x.1).fold(0f32, |a, b| a + b);
        let sum_f = sum as f32;
        println!("test_r_encoding: average {}", sum_f / size);
        println!("test_r_encoding: max is {}", values.iter().max().unwrap());

        let hist = utils::histogram(&v, 0.0, 30.0, 30);
        Chart::new(380, 100, 0.0, 30.0)
        .lineplot(&Shape::Bars(&hist))
        .nice();
    }

    #[test]
    fn test_ristretto_schnorr() {
        let csprng = OsRng;
        let group = RistrettoGroup;
        let g = group.generator();
        let secret = group.rnd_exp(csprng);
        let public = g.mod_pow(&secret, &group.modulus());
        let schnorr = group.schnorr_prove(&secret, &public, &g, csprng);
        let verified = group.schnorr_verify(&public, &g, &schnorr);
        assert!(verified == true);
        let public_false = group.generator().mod_pow(&group.rnd_exp(csprng), &group.modulus());
        let verified_false = group.schnorr_verify(&public_false, &g, &schnorr);
        assert!(verified_false == false);
    }

    #[test]
    fn test_ristretto_chaumpedersen() {
        let csprng = OsRng;
        let group = RistrettoGroup;
        let g1 = group.generator();
        let g2 = group.rnd(csprng);
        let secret = group.rnd_exp(csprng);
        let public1 = g1.mod_pow(&secret, &group.modulus());
        let public2 = g2.mod_pow(&secret, &group.modulus());
        let proof = group.cp_prove(&secret, &public1, &public2, &g1, &g2, csprng);
        let verified = group.cp_verify(&public1, &public2, &g1, &g2, &proof);
        
        assert!(verified == true);
        let public_false = group.generator().mod_pow(&group.rnd_exp(csprng), &group.modulus());
        let verified_false = group.cp_verify(&public1, &public_false, &g1, &g2, &proof);
        assert!(verified_false == false);
    }

    #[test]
    fn test_ristretto_vdecryption() {
        let csprng = OsRng;
        let group = RistrettoGroup;
        
        let sk = group.gen_key(csprng);
        let pk = PublicKey::from(&sk.public_value, &group);
        
        let text = "16 byte message!";
        let plaintext = group.encode(to_u8_16(text.as_bytes().to_vec()));
        
        let c = pk.encrypt(plaintext, csprng);    
        let (d, proof) = sk.decrypt_and_prove(&c, csprng);

        let dec_factor = c.a.div(&d, &group.modulus()).modulo(&group.modulus());

        let verified = group.cp_verify(&pk.value, &dec_factor, &group.generator(), &c.b, &proof);
        let recovered = String::from_utf8(group.decode(d).to_vec());
        assert!(verified == true);
        assert_eq!(recovered.unwrap(), text);
    }

    #[test]
    fn test_ristretto_distributed() {
        let csprng = OsRng;
        let group = RistrettoGroup;
        
        let km1 = Keymaker::gen(&group, OsRng);
        let km2 = Keymaker::gen(&group, OsRng);
        let (pk1, proof1) = km1.share(csprng);
        let (pk2, proof2) = km2.share(csprng);
        
        let verified1 = group.schnorr_verify(&pk1.value, &group.generator(), &proof1);
        let verified2 = group.schnorr_verify(&pk2.value, &group.generator(), &proof2);
        assert!(verified1 == true);
        assert!(verified2 == true);
        
        let text = "16 byte message!";
        let plaintext = group.encode(to_u8_16(text.as_bytes().to_vec()));
        
        let pk1_value = &pk1.value.clone();
        let pk2_value = &pk2.value.clone();
        let pks = vec![pk1, pk2];
        
        let pk_combined = Keymaker::combine_pks(&group, pks);
        let c = pk_combined.encrypt(plaintext, csprng);
        
        let (dec_f1, proof1) = km1.decryption_factor(&c, csprng);
        let (dec_f2, proof2) = km2.decryption_factor(&c, csprng);
        
        let verified1 = group.cp_verify(pk1_value, &dec_f1, &group.generator(), &c.b, &proof1);
        let verified2 = group.cp_verify(pk2_value, &dec_f2, &group.generator(), &c.b, &proof2);
        assert!(verified1 == true);
        assert!(verified2 == true);
        
        let decs = vec![dec_f1, dec_f2];
        let d = Keymaker::joint_dec(&group, decs, c);
        let recovered = String::from_utf8(group.decode(d).to_vec());
        assert_eq!(recovered.unwrap(), text);
    }
    
    #[test]
    fn test_ristretto_distributed_serde() {
        let csprng = OsRng;
        let group = RistrettoGroup;
        
        let km1 = Keymaker::gen(&group, OsRng);
        let km2 = Keymaker::gen(&group, OsRng);
        let (pk1, proof1) = km1.share(csprng);
        let (pk2, proof2) = km2.share(csprng);

        let share1 = Keyshare {
            share: pk1,
            proof: proof1
        };
        let share2 = Keyshare {
            share: pk2,
            proof: proof2
        };

        let share1_b = bincode::serialize(&share1).unwrap();
        let share2_b = bincode::serialize(&share2).unwrap();
        let share1_d: Keyshare<RistrettoPoint, RistrettoGroup> = bincode::deserialize(&share1_b).unwrap();
        let share2_d: Keyshare<RistrettoPoint, RistrettoGroup> = bincode::deserialize(&share2_b).unwrap();
        
        let verified1 = group.schnorr_verify(&share1_d.share.value, &group.generator(), &share1_d.proof);
        let verified2 = group.schnorr_verify(&share2_d.share.value, &group.generator(), &share2_d.proof);
        assert!(verified1 == true);
        assert!(verified2 == true);
        
        let text = "16 byte message!";
        let plaintext = group.encode(to_u8_16(text.as_bytes().to_vec()));
        let pk1_value = &share1_d.share.value.clone();
        let pk2_value = &share2_d.share.value.clone();
        let pks = vec![share1_d.share, share2_d.share];
        
        let pk_combined = Keymaker::combine_pks(&group, pks);
        let c = pk_combined.encrypt(plaintext, csprng);
        
        let (dec_f1, proof1) = km1.decryption_factor(&c, csprng);
        let (dec_f2, proof2) = km2.decryption_factor(&c, csprng);

        let pd1 = PartialDecryption {
            pd_ballots: vec![dec_f1],
            proofs: vec![proof1]
        };
        let pd2 = PartialDecryption {
            pd_ballots: vec![dec_f2],
            proofs: vec![proof2]
        };

        let pd1_b = bincode::serialize(&pd1).unwrap();
        let pd2_b = bincode::serialize(&pd2).unwrap();
        let mut pd1_d: PartialDecryption<RistrettoPoint> = bincode::deserialize(&pd1_b).unwrap();
        let mut pd2_d: PartialDecryption<RistrettoPoint> = bincode::deserialize(&pd2_b).unwrap();
        
        let verified1 = group.cp_verify(pk1_value, &pd1_d.pd_ballots[0], &group.generator(), 
            &c.b, &pd1_d.proofs[0]);
        let verified2 = group.cp_verify(pk2_value, &pd2_d.pd_ballots[0], &group.generator(), 
            &c.b, &pd2_d.proofs[0]);
        assert!(verified1 == true);
        assert!(verified2 == true);
        
        let decs = vec![pd1_d.pd_ballots.remove(0), pd2_d.pd_ballots.remove(0)];
        let d = Keymaker::joint_dec(&group, decs, c);

        let recovered = String::from_utf8(group.decode(d).to_vec());
        assert_eq!(recovered.unwrap(), text);
    }

    #[test]
    fn test_identity() {
        let mut csprng = OsRng;
        let x = RistrettoPoint::random(&mut csprng);
        assert_eq!(x + RistrettoPoint::identity(), x);
    }

    #[test]
    fn test_ristretto_shuffle_serde() {
        let csprng = OsRng;
        let group = RistrettoGroup;
        let exp_hasher = &*group.exp_hasher();
        
        let sk = group.gen_key(csprng);
        let pk = PublicKey::from(&sk.public_value, &group);

        let es = Ballots::random_ristretto(10, &group).ciphertexts;
        
        let hs = generators(es.len() + 1, &group, csprng);
        let shuffler = Shuffler {
            pk: &pk,
            generators: &hs,
            hasher: exp_hasher
        };
        let (e_primes, rs, perm) = shuffler.gen_shuffle(&es, csprng);
        let proof = shuffler.gen_proof(&es, &e_primes, &rs, &perm, csprng);
        let ok = shuffler.check_proof(&proof, &es, &e_primes);

        let mix = Mix{
            mixed_ballots: e_primes,
            proof: proof
        };
        
        let _group_b = bincode::serialize(&group).unwrap();
        let _sk_b = bincode::serialize(&sk).unwrap();
        let pk_b = bincode::serialize(&pk).unwrap();
        let es_b = bincode::serialize(&es).unwrap();
        let mix_b = bincode::serialize(&mix).unwrap();        

        assert!(ok == true);

        let pk_d: PublicKey<RistrettoPoint, RistrettoGroup> = bincode::deserialize(&pk_b).unwrap();
        let es_d: Vec<Ciphertext<RistrettoPoint>> = bincode::deserialize(&es_b).unwrap();
        let mix_d: Mix<RistrettoPoint> = bincode::deserialize(&mix_b).unwrap();
        
        let shuffler_d = Shuffler {
            pk: &pk_d,
            generators: &hs,
            hasher: exp_hasher
        };
        let ok_d = shuffler_d.check_proof(&mix_d.proof, &es_d, &mix_d.mixed_ballots);
        
        assert!(ok_d == true);
    }
}