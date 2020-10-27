use rand::Rng;
use rand_core::{OsRng};
use rug::Integer;
use serde::{Deserialize, Serialize};

mod elgamal;
mod hashing;
mod ristretto_elgamal;
mod rug_elgamal;
mod dto;
mod zkp;

use elgamal::*;
use ristretto_elgamal::*;
use hashing::{ByteSource, ExpFromHash};

fn main() {
}

pub struct YChallengeInput<'a, E: Element + ByteSource> {
    pub es: &'a Vec<Ciphertext<E>>,
    pub e_primes: &'a Vec<Ciphertext<E>>,
    pub cs: &'a Vec<E>,
    pub c_hats: &'a Vec<E>,
    pub pk: &'a dyn PublicK<E, OsRng>
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TValues<E: Element + ByteSource> {
    pub t1: E,
    pub t2: E,
    pub t3: E,
    pub t4_1: E,
    pub t4_2: E,
    pub t_hats: Vec<E>
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Responses<X: Exponent> {
    s1: X,
    s2: X,
    s3: X,
    s4: X,
    s_hats: Vec<X>,
    s_primes: Vec<X>
}

// FIXME cannot get type safety and serde to work at once, so we're using standalone exponents here
// type safety is maintained in gen/check proof signatures
#[derive(Serialize, Deserialize, Clone)]
pub struct Proof<E: Element + ByteSource, X: Exponent> {
    t: TValues<E>,
    s: Responses<X>,
    cs: Vec<E>,
    c_hats: Vec<E>
}

pub fn gen_proof<E: Element>(es: &Vec<Ciphertext<E>>, e_primes: &Vec<Ciphertext<E>>, r_primes: &Vec<E::Exp>, 
    perm: &Vec<usize>, pk: &dyn PublicK<E, OsRng>, generators: &Vec<E>, hasher: &dyn ExpFromHash<E::Exp>) -> Proof<E, E::Exp> {

    let csprng = OsRng;
    
    let group = pk.group();
    
    #[allow(non_snake_case)]
    let N = es.len();
    
    let h_generators = &generators[1..];
    let h_initial = &generators[0];
    
    assert!(N == e_primes.len());
    assert!(N == r_primes.len());
    assert!(N == perm.len());
    assert!(N == h_generators.len());

    let (cs, rs) = gen_commitments(&perm, h_generators, group);
    let us = hashing::shuffle_proof_us(&es, &e_primes, &cs, hasher, N);
    
    let mut u_primes: Vec<&E::Exp> = Vec::with_capacity(N);
    for &i in perm.iter() {
        u_primes.push(&us[i]);
    }
    
    let (c_hats, r_hats) = gen_commitment_chain(h_initial, &u_primes, group);
    
    let mut r_bar = E::Exp::add_identity();
    for i in 0..rs.len() {
        r_bar = r_bar.add(&rs[i]);
    }
    r_bar = r_bar.modulo(&group.exp_modulus());
    
    let mut vs = vec![E::Exp::mul_identity();perm.len()];
    for i in (0..(perm.len() - 1)).rev() {
        vs[i] = u_primes[i+1].mul(&vs[i+1]).modulo(&group.exp_modulus());
    }
    
    let mut r_hat: E::Exp = r_hats[0].mul(&vs[0]);
    for i in 1..r_hats.len() {
        r_hat = r_hat.add(&r_hats[i].mul(&vs[i]));
    }
    r_hat = r_hat.modulo(&group.exp_modulus());
    
    let mut r_tilde: E::Exp = rs[0].mul(&us[0]);
    for i in 1..rs.len() {
        r_tilde = r_tilde.add(&rs[i].mul(&us[i]));
    }
    r_tilde = r_tilde.modulo(&group.exp_modulus());
    
    let mut r_prime: E::Exp = r_primes[0].mul(&us[0]);
    for i in 1..r_primes.len() {
        r_prime = r_prime.add(&r_primes[i].mul(&us[i]));
    }
    r_prime = r_prime.modulo(&group.exp_modulus());
    
    let omegas = vec![group.rnd_exp(csprng);4];
    let omega_hats = vec![group.rnd_exp(csprng);N];
    let omega_primes = vec![group.rnd_exp(csprng);N];

    let t1 = group.generator().mod_pow(&omegas[0], &group.modulus());
    let t2 = group.generator().mod_pow(&omegas[1], &group.modulus());

    let mut t3_temp = h_generators[0].mod_pow(&omega_primes[0], &group.modulus());
    let mut t4_1_temp = e_primes[0].a.mod_pow(&omega_primes[0], &group.modulus());
    let mut t4_2_temp = e_primes[0].b.mod_pow(&omega_primes[0], &group.modulus());
        
    for i in 1..N {
        t3_temp = t3_temp.mul(&h_generators[i].mod_pow(&omega_primes[i], &group.modulus()))
            .modulo(&group.modulus());
        t4_1_temp = t4_1_temp.mul(&e_primes[i].a.mod_pow(&omega_primes[i], &group.modulus()))
            .modulo(&group.modulus());
        t4_2_temp = t4_2_temp.mul(&e_primes[i].b.mod_pow(&omega_primes[i], &group.modulus()))
            .modulo(&group.modulus());
    }
    
    let t3 = (group.generator().mod_pow(&omegas[2], &group.modulus())).mul(&t3_temp)
        .modulo(&group.modulus());
    let t4_1 = (pk.value().mod_pow(&omegas[3].neg(), &group.modulus())).mul(&t4_1_temp)
        .modulo(&group.modulus());
    let t4_2 = (group.generator().mod_pow(&omegas[3].neg(), &group.modulus())).mul(&t4_2_temp)
        .modulo(&group.modulus());

    let mut t_hats: Vec<E> = Vec::with_capacity(N);
    for i in 0..c_hats.len() {
        let previous_c = if i == 0 {
            h_initial 
        } else {
            &c_hats[i-1]
        };
        
        let next = (group.generator().mod_pow(&omega_hats[i], &group.modulus()))
                .mul(&previous_c.mod_pow(&omega_primes[i], &group.modulus()))
                .modulo(&group.modulus());
        
        t_hats.push(next);
    }
 
    let y = YChallengeInput {
        es: es,
        e_primes: e_primes,
        cs: &cs,
        c_hats: &c_hats,
        pk: pk
    };

    let t = TValues {
        t1,
        t2,
        t3,
        t4_1,
        t4_2,
        t_hats
    };

    let c: E::Exp = hashing::shuffle_proof_challenge(&y, &t, hasher);
 
    let s1 = omegas[0].add(&c.mul(&r_bar)).modulo(&group.exp_modulus());
    let s2 = omegas[1].add(&c.mul(&r_hat)).modulo(&group.exp_modulus());
    let s3 = omegas[2].add(&c.mul(&r_tilde)).modulo(&group.exp_modulus());
    let s4 = omegas[3].add(&c.mul(&r_prime)).modulo(&group.exp_modulus());

    let mut s_hats: Vec<E::Exp> = Vec::with_capacity(N);
    let mut s_primes: Vec<E::Exp> = Vec::with_capacity(N);
    
    for i in 0..N {
        s_hats.push(omega_hats[i].add(&c.mul(&r_hats[i])).modulo(&group.exp_modulus()));
        s_primes.push(omega_primes[i].add(&c.mul(&u_primes[i])).modulo(&group.exp_modulus()));
    }

    let s = Responses {
        s1,
        s2,
        s3,
        s4,
        s_hats,
        s_primes
    };

    Proof {
        t,
        s,
        cs,
        c_hats
    }
}

pub fn check_proof<E: Element>(proof: &Proof<E, E::Exp>, es: &Vec<Ciphertext<E>>, e_primes: &Vec<Ciphertext<E>>, 
    pk: &dyn PublicK<E, OsRng>, generators: &Vec<E>, hasher: &dyn ExpFromHash<E::Exp>) -> bool {
    
    let group = pk.group();
    
    #[allow(non_snake_case)]
    let N = es.len();
    
    let h_generators = &generators[1..];
    let h_initial = &generators[0];
    
    assert!(N == e_primes.len());
    assert!(N == h_generators.len());

    let us: Vec<E::Exp> = hashing::shuffle_proof_us(es, e_primes, &proof.cs, hasher, N);
    
    let mut c_bar_num: E = proof.cs[0].clone();
    let mut c_bar_den: E = h_generators[0].clone();
    let mut u: E::Exp = us[0].clone();
    let mut c_tilde: E = proof.cs[0].mod_pow(&us[0], &group.modulus());
    let mut a_prime: E = es[0].a.mod_pow(&us[0], &group.modulus());
    let mut b_prime: E = es[0].b.mod_pow(&us[0], &group.modulus());
    
    let mut t_tilde3_temp: E = h_generators[0].mod_pow(&proof.s.s_primes[0], &group.modulus());
    let mut t_tilde41_temp: E = e_primes[0].a.mod_pow(&proof.s.s_primes[0], &group.modulus());
    let mut t_tilde42_temp: E = e_primes[0].b.mod_pow(&proof.s.s_primes[0], &group.modulus());
     
    
    for i in 1..N {
        c_bar_num = c_bar_num.mul(&proof.cs[i]).modulo(&group.modulus());
        c_bar_den = c_bar_den.mul(&h_generators[i]).modulo(&group.modulus());
        u = u.mul(&us[i]).modulo(&group.exp_modulus());
        c_tilde = c_tilde.mul(&proof.cs[i].mod_pow(&us[i], &group.modulus()))
            .modulo(&group.modulus());
        a_prime = a_prime.mul(&es[i].a.mod_pow(&us[i], &group.modulus()))
            .modulo(&group.modulus());
        b_prime = b_prime.mul(&es[i].b.mod_pow(&us[i], &group.modulus()))
            .modulo(&group.modulus());
        t_tilde3_temp = t_tilde3_temp.mul(&h_generators[i].mod_pow(&proof.s.s_primes[i], &group.modulus()))
            .modulo(&group.modulus());
        t_tilde41_temp = t_tilde41_temp.mul(&e_primes[i].a.mod_pow(&proof.s.s_primes[i], &group.modulus()))
            .modulo(&group.modulus());
        t_tilde42_temp = t_tilde42_temp.mul(&e_primes[i].b.mod_pow(&proof.s.s_primes[i], &group.modulus()))
            .modulo(&group.modulus());
        
    }

    let c_bar = c_bar_num.div(&c_bar_den, &group.modulus())
        .modulo(&group.modulus());
    
    let c_hat = proof.c_hats[N - 1].div(&h_initial.mod_pow(&u, &group.modulus()), &group.modulus())
        .modulo(&group.modulus());
        
    let y = YChallengeInput {
        es: es,
        e_primes: e_primes,
        cs: &proof.cs,
        c_hats: &proof.c_hats,
        pk: pk
    };

    let c = hashing::shuffle_proof_challenge(&y, &proof.t, hasher);
    
    let t_prime1 = (c_bar.mod_pow(&c.neg(), &group.modulus()))
        .mul(&group.generator().mod_pow(&proof.s.s1, &group.modulus()))
        .modulo(&group.modulus());
    
    let t_prime2 = (c_hat.mod_pow(&c.neg(), &group.modulus()))
        .mul(&group.generator().mod_pow(&proof.s.s2, &group.modulus()))
        .modulo(&group.modulus());
    
    let t_prime3 = (c_tilde.mod_pow(&c.neg(), &group.modulus()))
        .mul(&group.generator().mod_pow(&proof.s.s3, &group.modulus()))
        .mul(&t_tilde3_temp)
        .modulo(&group.modulus());
    
    let t_prime41 = (a_prime.mod_pow(&c.neg(), &group.modulus()))
        .mul(&pk.value().mod_pow(&proof.s.s4.neg(), &group.modulus()))
        .mul(&t_tilde41_temp)
        .modulo(&group.modulus());

    let t_prime42 = (b_prime.mod_pow(&c.neg(), &group.modulus()))
        .mul(&group.generator().mod_pow(&proof.s.s4.neg(), &group.modulus()))
        .mul(&t_tilde42_temp)
        .modulo(&group.modulus());
    
    let mut t_hat_primes = Vec::with_capacity(N);
    for i in 0..N {
        let c_term = if i == 0 {
            h_initial
        } else {
            &proof.c_hats[i - 1]
        };
        let next = (proof.c_hats[i].mod_pow(&c.neg(), &group.modulus())) 
            .mul(&group.generator().mod_pow(&proof.s.s_hats[i], &group.modulus()))
            .mul(&c_term.mod_pow(&proof.s.s_primes[i], &group.modulus()))
            .modulo(&group.modulus());
        
        t_hat_primes.push(next);
    }

    let mut checks = Vec::with_capacity(5 + N);
    checks.push(proof.t.t1.eq(&t_prime1));
    checks.push(proof.t.t2.eq(&t_prime2));
    checks.push(proof.t.t3.eq(&t_prime3));
    checks.push(proof.t.t4_1.eq(&t_prime41));
    checks.push(proof.t.t4_2.eq(&t_prime42));
    for i in 0..N {
        checks.push(proof.t.t_hats[i].eq(&t_hat_primes[i]));
    }
    
    println!("{:?}", checks);
    
    !checks.contains(&false)
}

pub fn gen_permutation(size: usize) -> Vec<usize> {
    let mut ret = Vec::with_capacity(size);
    let mut rng = rand::thread_rng();

    let mut ordered: Vec<usize> = (0..size).collect();

    for i in 0..size {
        let k = rng.gen_range(i, size);
        let j = ordered[k];
        ordered[k] = ordered[i];
        ret.push(j);
    }

    return ret;
}

pub fn gen_shuffle<E: Element>(ciphertexts: &Vec<Ciphertext<E>>, pk: &dyn PublicK<E, OsRng>) -> (Vec<Ciphertext<E>>, Vec<E::Exp>, Vec<usize>) {
    let csprng = OsRng;
    let perm: Vec<usize> = gen_permutation(ciphertexts.len());

    let mut e_primes = Vec::with_capacity(ciphertexts.len());
    let mut rs_temp: Vec<Option<E::Exp>> = vec![None;ciphertexts.len()];
    let group = pk.group();

    for i in 0..perm.len() {
        let c = &ciphertexts[perm[i]];

        let r = group.rnd_exp(csprng);
        
        let a = c.a.mul(&pk.value().mod_pow(&r, &group.modulus()))
            .modulo(&group.modulus());
        let b = c.b.mul(&group.generator().mod_pow(&r, &group.modulus()))
            .modulo(&group.modulus());
        
        let c_ = Ciphertext {
            a: a, 
            b: b
        };
        e_primes.push(c_);
        rs_temp[perm[i]] = Some(r);
    }

    let mut rs = Vec::with_capacity(ciphertexts.len());

    for _ in 0..perm.len() {
     
        let r = rs_temp.remove(0);
        rs.push(r.unwrap());

    }
    
    (e_primes, rs, perm)
}

pub fn gen_commitments<E: Element>(perm: &Vec<usize>, generators: &[E], group: &dyn Group<E, OsRng>)  -> (Vec<E>, Vec<E::Exp>) {
    let csprng = OsRng;

    assert!(generators.len() == perm.len());
    
    let mut rs: Vec<Option<E::Exp>> = vec![None;perm.len()];
    let mut cs: Vec<Option<E>> = vec![None;perm.len()];
    
    for i in 0..perm.len() {
        let r = group.rnd_exp(csprng);
        let c = generators[i].mul(&group.generator().mod_pow(&r, &group.modulus()))
            .modulo(&group.modulus());
        
        rs[perm[i]] = Some(r);
        cs[perm[i]] = Some(c);
    }

    let mut ret1: Vec<E> = Vec::with_capacity(perm.len());
    let mut ret2: Vec<E::Exp> = Vec::with_capacity(perm.len());
    
    for _ in 0..perm.len() {
        let c = cs.remove(0);
        let r = rs.remove(0);

        ret1.push(c.unwrap());
        ret2.push(r.unwrap());
    }

    (ret1, ret2)
}

pub fn gen_commitment_chain<E: Element>(initial: &E, us: &Vec<&E::Exp>, group: &dyn Group<E, OsRng>)  -> (Vec<E>, Vec<E::Exp>) {
    let csprng = OsRng;
    let mut cs: Vec<E> = Vec::with_capacity(us.len());
    let mut rs: Vec<E::Exp> = Vec::with_capacity(us.len());
    
    for i in 0..us.len() {
        let r = group.rnd_exp(csprng);
        let c_temp = if i == 0 {
            initial
        } else {
            &cs[i-1]
        };
        
        let first = group.generator().mod_pow(&r, &group.modulus())
            .modulo(&group.modulus());
        let second = c_temp.mod_pow(&us[i], &group.modulus()).
            modulo(&group.modulus());
        let c = first.mul(&second).modulo(&group.modulus());

        cs.push(c);
        rs.push(r);
    }

    (cs, rs)
}

// FIXME not kosher
pub fn generators<E: Element>(size: usize, group: &dyn Group<E, OsRng>) -> Vec<E> {
    let csprng = OsRng;
    let mut ret: Vec<E> = Vec::with_capacity(size);
    
    for _ in 0..size {
        let g = group.rnd(csprng);
        ret.push(g);
    }

    ret
}

#[test]
fn test_shuffle_ristretto() {
    
    let csprng = OsRng;
    let group = RistrettoGroup;
    let exp_hasher = &*group.exp_hasher();
        
    // let sk = PrivateKey::random(&group, csprng);
    // let pk = PublicKey::from(&sk);

    let sk2 = group.gen_key(csprng);
    let pk2 = sk2.get_public_key();

    let mut es = Vec::with_capacity(10);

    let n = 100;

    for _ in 0..n {
        let plaintext = group.rnd(csprng);
        let c = pk2.encrypt(plaintext, csprng);
        es.push(c);
    }

    let hs = generators(es.len() + 1, &group);
    let (e_primes, rs, perm) = gen_shuffle(&es, &*pk2);
    let proof = gen_proof(&es, &e_primes, &rs, &perm, &*pk2, &hs, exp_hasher);
    let ok = check_proof(&proof, &es, &e_primes, &*pk2, &hs, exp_hasher);

    assert!(ok == true);
}

use std::time::{Instant};

use rug_elgamal::*;

#[test]
fn test_shuffle_mg() {

    let group = RugGroup::default();
    let exp_hasher = &*group.exp_hasher();
    let csprng = OsRng;
        
    // let sk = PrivateKey::random(&group, csprng);
    // let pk = PublicKey::from(&sk);

    // let sk2 = group.gen_key(csprng);
    // let pk2 = sk2.get_public_key();

    /* let sk2 = PrivateKeyRug {
        value: group.rnd_exp(csprng),
        group: group.clone()
    };*/
    let sk2 = group.gen_key_conc(csprng);
    let pk2 = sk2.get_public_key_conc();

    let shuffle_tests = 1;
    let n = 100;
 
    for _ in 0..shuffle_tests {
    
        let mut es: Vec<Ciphertext<Integer>> = Vec::with_capacity(10);

        let mut now = Instant::now();
        
        for _ in 0..n {
            let plaintext: Integer = group.encode(group.rnd_exp(csprng));
            let c = pk2.encrypt(plaintext, csprng);
            es.push(c);
        }
        println!("encrypted {} ciphertexts in {} seconds", n, now.elapsed().as_secs());
        now = Instant::now();
        let hs = generators(es.len() + 1, &group);
        println!("generators for {} ciphertexts in {} seconds", n, now.elapsed().as_secs());
        now = Instant::now();
        let (e_primes, rs, perm) = gen_shuffle(&es, &pk2);
        println!("gen shuffle {} ciphertexts in {} seconds", n, now.elapsed().as_secs());
        now = Instant::now();
        let proof = gen_proof(&es, &e_primes, &rs, &perm, &pk2, &hs, exp_hasher);
        println!("gen proof {} ciphertexts in {} seconds", n, now.elapsed().as_secs());
        now = Instant::now();
        let ok = check_proof(&proof, &es, &e_primes, &pk2, &hs, exp_hasher);
        println!("check proof {} ciphertexts in {} seconds", n, now.elapsed().as_secs());

        assert!(ok == true);
    }
    
    println!("Ran {} shuffle tests, ciphertexts = {}", shuffle_tests, n);
}
