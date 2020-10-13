#[macro_use]
extern crate lazy_static;

use rand_core::{CryptoRng, OsRng, RngCore};
use rug::{
    rand::{RandGen, RandState},
    Integer,
};
struct OsGenerator;

impl RandGen for OsGenerator {
    fn gen(&mut self) -> u32 {
        let mut csprng = OsRng;
        return csprng.next_u32();
    }
}

fn modulus(a: Integer, p: Integer) -> Integer {
    let mut rem = a.div_rem(p.clone()).1;
    
    if rem < 0 {
        rem = rem + p;
    }

    rem
}

fn encode(m: Integer, p: Integer) -> Integer {
    let jacobi = m.clone().jacobi(&p);
    modulus(jacobi * m, p)
}

fn decode(m: Integer, q: Integer, p: Integer) -> Integer {
    if m > q {
        p - m
    }
    else {
        m
    }
}

// https://github.com/bfh-evg/unicrypt/blob/2c9b223c1abc6266aa56ace5562200a5050a0c2a/src/main/java/ch/bfh/unicrypt/helper/prime/SafePrime.java
const P_STR: &str = "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF324E7738926CFBE5F4BF8D8D8C31D763DA06C80ABB1185EB4F7C7B5757F5958490CFD47D7C19BB42158D9554F7B46BCED55C4D79FD5F24D6613C31C3839A2DDF8A9A276BCFBFA1C877C56284DAB79CD4C2B3293D20E9E5EAF02AC60ACC93ED874422A52ECB238FEEE5AB6ADD835FD1A0753D0A8F78E537D2B95BB79D8DCAEC642C1E9F23B829B5C2780BF38737DF8BB300D01334A0D0BD8645CBFA73A6160FFE393C48CBBBCA060F0FF8EC6D31BEB5CCEED7F2F0BB088017163BC60DF45A0ECB1BCD289B06CBBFEA21AD08E1847F3F7378D56CED94640D6EF0D3D37BE69D0063";
const Q_STR: &str = "5bf0a8b1457695355fb8ac404e7a79e3b1738b079c5a6d2b53c26c8228c867f799273b9c49367df2fa5fc6c6c618ebb1ed0364055d88c2f5a7be3dababfacac24867ea3ebe0cdda10ac6caaa7bda35e76aae26bcfeaf926b309e18e1c1cd16efc54d13b5e7dfd0e43be2b1426d5bce6a6159949e9074f2f5781563056649f6c3a21152976591c7f772d5b56ec1afe8d03a9e8547bc729be95caddbcec6e57632160f4f91dc14dae13c05f9c39befc5d98068099a50685ec322e5fd39d30b07ff1c9e2465dde5030787fc763698df5ae6776bf9785d84400b8b1de306fa2d07658de6944d8365dff510d68470c23f9fb9bc6ab676ca3206b77869e9bdf34e8031";

lazy_static! {
    // static ref P: Integer = Integer::from_str_radix(P_STR, 16).unwrap();
    // static ref Q: Integer = Integer::from_str_radix(Q_STR, 16).unwrap();
    // static ref G: Integer = Integer::from(3);
}


fn main() {
    let mut gen = OsGenerator;
    let mut state = RandState::new_custom(&mut gen);
    
    let p = Integer::from_str_radix(P_STR, 16).unwrap();
    let q: Integer = (p.clone() - 1) / 2;
    let g = Integer::from(3);
    assert!(g.clone().jacobi(&p) == 1);

    let sk = q.clone().random_below(&mut state);
    let pk = g.clone().pow_mod(&sk, &p).unwrap();
    let m = q.clone().random_below(&mut state);
    
    let m_encoded = encode(m.clone(), p.clone());
    
    let r = q.clone().random_below(&mut state);
    
    let a = g.clone().pow_mod(&r, &p).unwrap();
    let b = modulus(m_encoded * pk.pow_mod(&r, &p).unwrap(), p.clone());

    let dec_factor = a.pow_mod(&sk, &p).unwrap();
    let mut m_ = modulus(b * dec_factor.invert(&p).unwrap(), p.clone());
    m_ = decode(m_, q, p);

    assert_eq!(m_, m);

}

use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_POINT};

// use serde::{Deserialize, Serialize};


trait Element {
    type Exp: Exponent;
    
    fn mult(&self, other: &Self) -> Self;
    fn div(&self, other: &Self) -> Self;
    fn mod_pow(&self, exp: &Self::Exp, modulus: &Self) -> Self;
    fn modulo(&self, modulus: &Self) -> Self;
}

trait Exponent {
    /* fn add(&self, other: &Self) -> Self;
    fn sub(&self, other: &Self) -> Self;
    fn mult(&self, other: &Self) -> Self;
    fn div(&self, other: &Self) -> Self;
    fn modulo(&self, modulus: &Self) -> Self;*/
}

impl Exponent for Integer {
}
impl Exponent for Scalar {
}

impl Element for Integer {
    type Exp = Integer;
    fn mult(&self, other: &Self) -> Self {
        self.clone() * other.clone()
    }
    fn div(&self, other: &Self) -> Self {
        self.clone() / other.clone()
    }
    fn mod_pow(&self, other: &Self::Exp, modulus: &Self) -> Self {
        self.clone().pow_mod(&other, modulus).unwrap()   
    }
    fn modulo(&self, modulus: &Self) -> Self {
        let (_, rem) = self.clone().div_rem(modulus.clone());
        rem
    }
}

impl Element for RistrettoPoint {
    type Exp = Scalar;
    fn mult(&self, other: &Self) -> Self {
        self + other
    }
    fn div(&self, other: &Self) -> Self {
        self - other
    }
    fn mod_pow(&self, other: &Self::Exp, _modulus: &Self) -> Self {
        self * other
    }
    fn modulo(&self, _modulus: &Self) -> Self {
        *self
    }
}

trait Group<E: Element, T: RngCore + CryptoRng> {
    fn generator(&self) -> E;
    fn rnd(&self, rng: T) -> E;
    fn modulus(&self) -> E;
    fn rnd_exp(&self, rng: T) -> E::Exp;
    fn exp_modulus(&self) -> E::Exp;
}

struct RugGroup {
    generator: Integer,
    modulus: Integer,
    modulus_exp: Integer
}

impl Group<Integer, OsRng> for RugGroup {
    fn generator(&self) -> Integer {
        self.generator.clone()
    }
    fn rnd(&self, _rng: OsRng) -> Integer {
        let mut gen: OsGenerator  = OsGenerator;
        let mut state = RandState::new_custom(&mut gen);
        
        self.modulus.clone().random_below(&mut state)
    }
    fn modulus(&self) -> Integer {
        self.modulus.clone()
    }
    fn rnd_exp(&self, _rng: OsRng) -> Integer {
        let mut gen: OsGenerator  = OsGenerator;
        let mut state = RandState::new_custom(&mut gen);
        
        self.modulus_exp.clone().random_below(&mut state)
    }
    fn exp_modulus(&self) -> Integer {
        self.modulus_exp.clone()
    }
}

struct RistrettoGroup;

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
}

struct PrivateKey<'a, E: Element, T: RngCore + CryptoRng> {
    value: E::Exp,
    group: &'a dyn Group<E, T>
}


impl<'a, E: Element, T: RngCore + CryptoRng> PrivateKey<'a, E, T> {
    pub fn random(group: &'a dyn Group<E, T>, rng: T) -> Self {
        PrivateKey {
            value: group.rnd_exp(rng), 
            group: group
        }
    }
    
    pub fn decrypt(&self, c: Ciphertext<E>) -> E {
        c.a.div(&c.b.mod_pow(&self.value, &self.group.modulus()))
    }
}

struct Ciphertext<E: Element> {
    a: E,
    b: E
}

struct PublicKey<'a, E: Element, T: RngCore + CryptoRng> {
    value: E,
    group: &'a dyn Group<E, T>
}

impl<'a, E: Element, T: RngCore + CryptoRng> PublicKey<'a, E, T> {

    pub fn encrypt(self, plaintext: E, rng: T) -> Ciphertext<E> {
        let randomness = self.group.rnd_exp(rng);
        Ciphertext {
            a: plaintext.mult(&self.value.mod_pow(&randomness, &self.group.modulus())),
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

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ec() {
        let csprng = OsRng;
        
        let p = Integer::from_str_radix(P_STR, 16).unwrap();
        let q = Integer::from_str_radix(Q_STR, 16).unwrap();
        let g = Integer::from(3);
        
        let rg2 = RugGroup {
            generator: g,
            modulus: p,
            modulus_exp: q
        };
        
        let rg = RistrettoGroup;
        
        let sk = PrivateKey::random(&rg2, csprng);
        let pk = PublicKey::from(&sk);
        
        let text = "this has to be exactly 32 bytes!";
        // let text = "phis has to be exactly 32 bytes!";
        println!("{:?}", text.as_bytes().len());

        // let plaintext = CompressedRistretto::from_slice(text.as_bytes());    
        let plaintext = Integer::from(12345);
        
        // let c = pk.encrypt(plaintext.decompress().unwrap(), csprng);
        let c = pk.encrypt(plaintext.clone(), csprng);
        let d = sk.decrypt(c);
        
        // let recovered = String::from_utf8(d.compress().as_bytes().to_vec());
        // assert_eq!(text, recovered.unwrap());
        assert_eq!(d, plaintext);

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

        let sk_ = PrivateKey {
            value: Scalar::from_bytes_mod_order(skb), 
            group: &rg
        };
        let c_ = Ciphertext {
            a: CompressedRistretto(a).decompress().unwrap(),
            b: CompressedRistretto(b).decompress().unwrap()
        };
        let d_: RistrettoPoint = sk_.decrypt(c_);
        let recovered_ = String::from_utf8(d_.compress().as_bytes().to_vec());
        assert_eq!(text, recovered_.unwrap());
        
    }
}