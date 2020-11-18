

#[cfg(test)]
mod tests {
    use curve25519_dalek::ristretto::{RistrettoPoint};
    use curve25519_dalek::scalar::Scalar;
    use rug::{Integer};
    use crate::elgamal::*;
    use crate::shuffler::*;
    use rand_core::{OsRng};

    use crate::group::*;
    use crate::rug_b::*;
    use crate::ristretto_b::*;

    #[test]
    fn test_rug_serde() {
        use bincode;
        let csprng = OsRng;
        let group = RugGroup::default();
        let exp_hasher = &*group.exp_hasher();
        
        let sk = group.gen_key_conc(csprng);
        let pk = sk.get_public_key_conc();

        let mut es: Vec<Ciphertext<Integer>> = Vec::with_capacity(10);
        
        for _ in 0..10 {
            let plaintext: Integer = group.encode(group.rnd_exp(csprng));
            let c = pk.encrypt(plaintext, csprng);
            es.push(c);
        }
        
        let hs = generators(es.len() + 1, &group);
        let shuffler = Shuffler {
            pk: &pk,
            generators: &hs,
            hasher: exp_hasher
        };
        let (e_primes, rs, perm) = shuffler.gen_shuffle(&es);
        let proof = shuffler.gen_proof(&es, &e_primes, &rs, &perm);
        
        let _group_b = bincode::serialize(&group).unwrap();
        let _sk_b = bincode::serialize(&sk).unwrap();
        let pk_b = bincode::serialize(&pk).unwrap();
        let es_b = bincode::serialize(&es).unwrap();
        let e_primes_b = bincode::serialize(&e_primes).unwrap();
        let proof_b = bincode::serialize(&proof).unwrap();
        
        let ok = shuffler.check_proof(&proof, &es, &e_primes);

        assert!(ok == true);

        let pk_d: PublicKeyRug = bincode::deserialize(&pk_b).unwrap();
        let es_d: Vec<Ciphertext<Integer>> = bincode::deserialize(&es_b).unwrap();
        let e_primes_d: Vec<Ciphertext<Integer>> = bincode::deserialize(&e_primes_b).unwrap();
        let proof_d: Proof<Integer, Integer> = bincode::deserialize(&proof_b).unwrap();

        let shuffler_d = Shuffler {
            pk: &pk_d,
            generators: &hs,
            hasher: exp_hasher
        };
        let ok_d = shuffler_d.check_proof(&proof_d, &es_d, &e_primes_d);

        assert!(ok_d == true);
    }

    #[test]
    fn test_ristretto_serde() {
        use bincode;
        let csprng = OsRng;
        let group = RistrettoGroup;
        let exp_hasher = &*group.exp_hasher();
        
        let sk = group.gen_key_conc(csprng);
        let pk = sk.get_public_key_conc();

        let mut es: Vec<Ciphertext<RistrettoPoint>> = Vec::with_capacity(10);
        
        for _ in 0..10 {
            let text = "16 byte message!";
            let plaintext = group.encode(to_u8_16(text.as_bytes().to_vec()));
            let c = pk.encrypt(plaintext, csprng);
            es.push(c);
        }
        
        let hs = generators(es.len() + 1, &group);
        let shuffler = Shuffler {
            pk: &pk,
            generators: &hs,
            hasher: exp_hasher
        };
        let (e_primes, rs, perm) = shuffler.gen_shuffle(&es);
        let proof = shuffler.gen_proof(&es, &e_primes, &rs, &perm);
        
        let _group_b = bincode::serialize(&group).unwrap();
        let _sk_b = bincode::serialize(&sk).unwrap();
        let pk_b = bincode::serialize(&pk).unwrap();
        let es_b = bincode::serialize(&es).unwrap();
        let e_primes_b = bincode::serialize(&e_primes).unwrap();
        let proof_b = bincode::serialize(&proof).unwrap();
        
        let ok = shuffler.check_proof(&proof, &es, &e_primes);

        assert!(ok == true);

        let pk_d: PublicKeyRistretto = bincode::deserialize(&pk_b).unwrap();
        let es_d: Vec<Ciphertext<RistrettoPoint>> = bincode::deserialize(&es_b).unwrap();
        let e_primes_d: Vec<Ciphertext<RistrettoPoint>> = bincode::deserialize(&e_primes_b).unwrap();
        let proof_d: Proof<RistrettoPoint, Scalar> = bincode::deserialize(&proof_b).unwrap();

        let shuffler_d = Shuffler {
            pk: &pk_d,
            generators: &hs,
            hasher: exp_hasher
        };
        let ok_d = shuffler_d.check_proof(&proof_d, &es_d, &e_primes_d);
        assert!(ok_d == true);
    }

    #[test]
    fn test_signature_serde() {
    }
}