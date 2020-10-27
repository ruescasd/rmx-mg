use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_POINT};

use crate::elgamal::*;
use crate::hashing::{ExpFromHash, RistrettoHasher};

#[derive(Serialize, Deserialize)]
pub struct PublicKeyRistretto {
    pub value: RistrettoPoint,
    pub group: RistrettoGroup
}

#[derive(Serialize, Deserialize)]
pub struct PrivateKeyRistretto {
    pub value: Scalar,
    pub group: RistrettoGroup
}

impl PrivateKeyRistretto {
    pub fn get_public_key_conc(&self) -> PublicKeyRistretto { 
        let value = self.group.generator().mod_pow(&self.value, &self.group.modulus());
        
        PublicKeyRistretto {
            value: value,
            group: self.group.clone()
        }
    }
}

impl PrivateK<RistrettoPoint, OsRng> for PrivateKeyRistretto {

    fn decrypt(&self, c: Ciphertext<RistrettoPoint>) -> RistrettoPoint {
        c.a.div(&c.b.mod_pow(&self.value, &self.group.modulus()), 
            &self.group.modulus()).modulo(&self.group.modulus())
    }
    fn value(&self) -> &Scalar {
        &self.value
    }
    fn group(&self) -> &dyn Group<RistrettoPoint, OsRng> {
        &self.group
    }
    fn get_public_key(&self) -> Box<dyn PublicK<RistrettoPoint, OsRng>> {
        let value = self.group.generator().mod_pow(&self.value, &self.group.modulus());
        
        Box::new(PublicKeyRistretto{
            value: value,
            group: self.group.clone()
        })
    }
}

impl PublicK<RistrettoPoint, OsRng> for PublicKeyRistretto {
    fn value(&self) -> &RistrettoPoint {
        &self.value
    }
    fn group(&self) -> &dyn Group<RistrettoPoint, OsRng> {
        &self.group
    }
}

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

    pub fn gen_key_conc(&self, rng: OsRng) -> PrivateKeyRistretto {
        PrivateKeyRistretto {
            value: self.rnd_exp(rng), 
            group: self.clone()
        }
    }
}

impl Group<RistrettoPoint, OsRng> for RistrettoGroup {
    fn generator(&self) -> RistrettoPoint {
        RISTRETTO_BASEPOINT_POINT
    }
    fn rnd(&self, mut rng: OsRng) -> RistrettoPoint {
        RistrettoPoint::random(&mut rng)
    }
    fn modulus(&self) -> RistrettoPoint {
        RistrettoPoint::default()
    }
    fn rnd_exp(&self, mut rng: OsRng) -> Scalar {
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
    fn decode(&self, ciphertext: RistrettoPoint) -> [u8; 16] {
        let compressed = ciphertext.compress();
        let slice = &compressed.as_bytes()[12..28];
        to_u8_16(slice.to_vec())
    }
    fn gen_key(&self, rng: OsRng) -> Box<dyn PrivateK<RistrettoPoint, OsRng>> {
        Box::new(PrivateKeyRistretto {
            value: self.rnd_exp(rng), 
            group: self.clone()
        })
    }

    fn exp_hasher(&self) -> Box<dyn ExpFromHash<Scalar>> {
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
    use super::*;
    
    #[test]
    fn test_elgamal_ristretto() {
        let csprng = OsRng;
        let group = RistrettoGroup;
        
        let sk = group.gen_key_conc(csprng);
        let pk = sk.get_public_key_conc();
        
        let text = "16 byte message!";
        let plaintext = group.encode(to_u8_16(text.as_bytes().to_vec()));
      
        let c = pk.encrypt(plaintext, csprng);    
        let d = sk.decrypt(c);
        
        let recovered = String::from_utf8(group.decode(d).to_vec());
        assert_eq!(text, recovered.unwrap());
    }

    #[test]
    fn test_js_encoding() {
        
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

        let sk_ = PrivateKeyRistretto {
            value: Scalar::from_bytes_mod_order(skb), 
            group: rg
        };
        let c_ = Ciphertext {
            a: CompressedRistretto(a).decompress().unwrap(),
            b: CompressedRistretto(b).decompress().unwrap()
        };
        
        let d_: RistrettoPoint = sk_.decrypt(c_);
        let recovered_ = String::from_utf8(d_.compress().as_bytes().to_vec());
        
        assert_eq!(text, recovered_.unwrap());
    }

    extern crate textplots;
    use textplots::{utils, Chart, Plot, Shape};

    #[test]
    fn test_r_encoding() {
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
    fn test_r_schnorr() {
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
    fn test_r_chaumpedersen() {
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
}