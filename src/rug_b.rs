use rand_core::{OsRng, RngCore};
use rug::{
    rand::{RandGen, RandState},
    Integer,
};
use serde::{Deserialize, Serialize};

use crate::hashing::{HashTo, RugHasher};
use crate::arithm::*;
use crate::elgamal::*;
use crate::group::*;
use crate::dist::*;

impl Element for Integer {
    type Exp = Integer;
    type Plaintext = Integer;

    fn mul(&self, other: &Self) -> Self {
        self.clone() * other.clone()
    }
    fn div(&self, other: &Self, modulus: &Self) -> Self {
        self.clone() * (other.clone().invert(modulus).unwrap())
    }
    fn mod_pow(&self, other: &Self::Exp, modulus: &Self) -> Self {
        let ret = self.clone().pow_mod(&other, modulus);

        ret.unwrap()
    }
    fn modulo(&self, modulus: &Self) -> Self {
        let (_, mut rem) = self.clone().div_rem(modulus.clone());
        if rem < 0 {
            rem = rem + modulus;
        }
        
        rem
    }
    fn eq(&self, other: &Integer) -> bool {
        self == other
    }
    fn mul_identity() -> Integer {
        Integer::from(1)
    }
}

impl Exponent for Integer {
    fn add(&self, other: &Integer) -> Integer {
        Integer::from(self + other)
    }
    fn sub(&self, other: &Integer) -> Integer {
        Integer::from(self - other)
    }
    fn neg(&self) -> Integer {
        Integer::from(-self)
    }
    fn mul(&self, other: &Integer) -> Integer {
        Integer::from(self * other)
    }
    fn modulo(&self, modulus: &Integer) -> Integer {
        let (_, mut rem) = self.clone().div_rem(modulus.clone());
        
        if rem < 0 {
            rem = rem + modulus;
        }
        
        rem
    }
    fn eq(&self, other: &Integer) -> bool {
        self == other
    }

    fn add_identity() -> Integer {
        Integer::from(0)
    }
    fn mul_identity() -> Integer {
        Integer::from(1)
    }
}

struct OsRandgen(OsRng);

impl RandGen for OsRandgen {
    fn gen(&mut self) -> u32 {
        return self.0.next_u32();
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RugGroup {
    pub generator: Integer,
    pub modulus: Integer,
    pub modulus_exp: Integer
}

impl RugGroup {

    // https://github.com/bfh-evg/unicrypt/blob/2c9b223c1abc6266aa56ace5562200a5050a0c2a/src/main/java/ch/bfh/unicrypt/helper/prime/SafePrime.java
    pub const P_STR: &'static str = "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF324E7738926CFBE5F4BF8D8D8C31D763DA06C80ABB1185EB4F7C7B5757F5958490CFD47D7C19BB42158D9554F7B46BCED55C4D79FD5F24D6613C31C3839A2DDF8A9A276BCFBFA1C877C56284DAB79CD4C2B3293D20E9E5EAF02AC60ACC93ED874422A52ECB238FEEE5AB6ADD835FD1A0753D0A8F78E537D2B95BB79D8DCAEC642C1E9F23B829B5C2780BF38737DF8BB300D01334A0D0BD8645CBFA73A6160FFE393C48CBBBCA060F0FF8EC6D31BEB5CCEED7F2F0BB088017163BC60DF45A0ECB1BCD289B06CBBFEA21AD08E1847F3F7378D56CED94640D6EF0D3D37BE69D0063";
    pub const Q_STR: &'static str = "5bf0a8b1457695355fb8ac404e7a79e3b1738b079c5a6d2b53c26c8228c867f799273b9c49367df2fa5fc6c6c618ebb1ed0364055d88c2f5a7be3dababfacac24867ea3ebe0cdda10ac6caaa7bda35e76aae26bcfeaf926b309e18e1c1cd16efc54d13b5e7dfd0e43be2b1426d5bce6a6159949e9074f2f5781563056649f6c3a21152976591c7f772d5b56ec1afe8d03a9e8547bc729be95caddbcec6e57632160f4f91dc14dae13c05f9c39befc5d98068099a50685ec322e5fd39d30b07ff1c9e2465dde5030787fc763698df5ae6776bf9785d84400b8b1de306fa2d07658de6944d8365dff510d68470c23f9fb9bc6ab676ca3206b77869e9bdf34e8031";
    
    pub fn default() -> RugGroup {
        let p = Integer::from_str_radix(Self::P_STR, 16).unwrap();
        let q = Integer::from_str_radix(Self::Q_STR, 16).unwrap();
        let g = Integer::from(3);
        
        assert!(g.clone().legendre(&p) == 1);

        RugGroup {
            generator: g,
            modulus: p.clone(),
            modulus_exp: q
        }
    }

    pub fn gen_key_conc(&self, rng: OsRng) -> PrivateKeyRug {
        PrivateKeyRug {
            value: self.rnd_exp(rng), 
            group: self.clone()
        }
    }
}

impl Group<Integer, OsRng> for RugGroup {
    fn generator(&self) -> Integer {
        self.generator.clone()
    }
    fn rnd(&self, _rng: OsRng) -> Integer {
        let mut gen: OsRandgen  = OsRandgen(_rng);
        let mut state = RandState::new_custom(&mut gen);
        
        self.encode(self.modulus_exp.clone().random_below(&mut state))
    }
    fn modulus(&self) -> Integer {
        self.modulus.clone()
    }
    fn rnd_exp(&self, _rng: OsRng) -> Integer {
        let mut gen: OsRandgen  = OsRandgen(_rng);
        let mut state = RandState::new_custom(&mut gen);
        
        self.modulus_exp.clone().random_below(&mut state)
    }
    fn exp_modulus(&self) -> Integer {
        self.modulus_exp.clone()
    }
    fn encode(&self, plaintext: Integer) -> Integer {
        assert!(plaintext < self.modulus_exp.clone() - 1);

        let notzero: Integer = plaintext + 1;
        let legendre = notzero.clone().legendre(&self.modulus());
        let product = legendre * notzero;
        
        // this syntax to disambiguate between traits
        Element::modulo(&product, &self.modulus())
    }
    fn decode(&self, plaintext: Integer) -> Integer {
        if plaintext > self.exp_modulus() {
            (self.modulus() - plaintext) - 1
        }
        else {
            plaintext - 1
        }
    }
    fn gen_key(&self, rng: OsRng) -> Box<dyn PrivateK<Integer, OsRng>> {
        Box::new(PrivateKeyRug {
            value: self.rnd_exp(rng), 
            group: self.clone()
        })
    }
    fn pk_from_value(&self, value: Integer) -> Box<dyn PublicK<Integer, OsRng>> {
        Box::new(PublicKeyRug {
            value: value,
            group: self.clone()
        })
    }
    
    fn exp_hasher(&self) -> Box<dyn HashTo<Integer>> {
        Box::new(RugHasher(self.modulus_exp.clone()))
    }
    
}

#[derive(Serialize, Deserialize)]
pub struct PublicKeyRug {
    pub value: Integer,
    pub group: RugGroup
}

#[derive(Serialize, Deserialize)]
pub struct PrivateKeyRug {
    pub value: Integer,
    pub group: RugGroup
}

impl PrivateKeyRug {
    pub fn get_public_key_conc(&self) -> PublicKeyRug { 
        let value = self.group.generator().mod_pow(&self.value, &self.group.modulus());
        
        PublicKeyRug {
            value: value,
            group: self.group.clone()
        }
    }
}

impl PrivateK<Integer, OsRng> for PrivateKeyRug {
    fn value(&self) -> &Integer {
        &self.value
    }
    fn group(&self) -> &dyn Group<Integer, OsRng> {
        &self.group
    }
    fn get_public_key(&self) -> Box<dyn PublicK<Integer, OsRng>> {
        let value = self.group.generator().mod_pow(&self.value, &self.group.modulus());
        
        Box::new(PublicKeyRug{
            value: value,
            group: self.group.clone()
        })
    }
}

impl PublicK<Integer, OsRng> for PublicKeyRug {
    fn value(&self) -> &Integer {
        &self.value
    }
    fn group(&self) -> &dyn Group<Integer, OsRng> {
        &self.group
    }
}

#[test]
#[should_panic]
fn test_encode_panic() {
    
    let rg = RugGroup::default();
    rg.encode(rg.exp_modulus() - 1);
}

#[test]
fn test_rug_elgamal() {
    let csprng = OsRng;
    let group = RugGroup::default();
    
    let sk = group.gen_key_conc(csprng);
    let pk = sk.get_public_key_conc();

    let plaintext = group.rnd_exp(csprng);
    
    let encoded = group.encode(plaintext.clone());
    let c = pk.encrypt(encoded.clone(), csprng);
    let d = group.decode(sk.decrypt(&c));
    assert_eq!(d, plaintext);

    let zero = Integer::from(0);
    let encoded_zero = group.encode(zero.clone());
    let c_zero = pk.encrypt(encoded_zero.clone(), csprng);
    let d_zero = group.decode(sk.decrypt(&c_zero));
    assert_eq!(d_zero, zero);
}

#[test]
fn test_rug_schnorr() {
    let csprng = OsRng;
    let group = RugGroup::default();
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
fn test_rug_chaumpedersen() {
    let csprng = OsRng;
    let group = RugGroup::default();
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
fn test_rug_vdecryption() {
    let csprng = OsRng;
    let group = RugGroup::default();
    
    let sk = group.gen_key_conc(csprng);
    let pk = sk.get_public_key_conc();

    let plaintext = group.rnd_exp(csprng);
    
    let encoded = group.encode(plaintext.clone());
    let c = pk.encrypt(encoded.clone(), csprng);
    let (d, proof) = sk.decrypt_and_prove(&c, csprng);

    let dec_factor =  Element::modulo(&c.a.div(&d, &group.modulus()), &group.modulus());
    let verified = group.cp_verify(&pk.value(), &dec_factor, &group.generator(), &c.b, &proof);
    
    assert!(verified == true);
    assert_eq!(group.decode(d), plaintext);
}

#[test]
fn test_rug_distributed() {
    let csprng = OsRng;
    let group = RugGroup::default();
    
    let km1 = Keym::gen(&group, OsRng);
    let km2 = Keym::gen(&group, OsRng);
    let (pk1, proof1) = km1.share(csprng);
    let (pk2, proof2) = km2.share(csprng);
    
    let verified1 = group.schnorr_verify(&pk1.value(), &group.generator(), &proof1);
    let verified2 = group.schnorr_verify(&pk2.value(), &group.generator(), &proof2);
    assert!(verified1 == true);
    assert!(verified2 == true);
    
    let plaintext = group.rnd_exp(csprng);
    
    let encoded = group.encode(plaintext.clone());
    
    let pk2_value = &pk2.value().clone();
    let other = vec![pk2];
    
    let pk_combined = km1.combine_pks(other);
    let c = pk_combined.encrypt(encoded.clone(), csprng);
    
    let (dec_f1, proof1) = km1.decryption_factor(&c, csprng);
    let (dec_f2, proof2) = km2.decryption_factor(&c, csprng);
    
    let verified1 = group.cp_verify(&pk1.value(), &dec_f1, &group.generator(), &c.b, &proof1);
    let verified2 = group.cp_verify(pk2_value, &dec_f2, &group.generator(), &c.b, &proof2);
    assert!(verified1 == true);
    assert!(verified2 == true);
    
    let decs = vec![dec_f1, dec_f2];
    let d = km1.joint_dec(decs, c);
    
    assert_eq!(group.decode(d), plaintext);
}

