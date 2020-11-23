use ed25519_dalek::PublicKey as SignaturePublicKey;
use rug::Integer;
use serde::{Deserialize, Serialize};

use crate::arithm::*;
use crate::elgamal::*;
use crate::group::*;
use crate::shuffler::*;

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct Config {
    pub id: [u8; 16],
    pub generator: Option<Integer>,
    pub modulus: Option<Integer>,
    pub modulus_exp: Option<Integer>,
    pub contests: u32, 
    pub ballotbox: SignaturePublicKey, 
    pub trustees: Vec<SignaturePublicKey>
}

#[derive(Serialize, Deserialize)]
pub struct Keyshare<E: Element, G: Group<E>> {
    pub share: PublicKey<E, G>,
    pub proof: Schnorr<E>
}

#[derive(Serialize, Deserialize)]
pub struct Mix<E: Element> {
    pub mixed_ballots: Vec<Ciphertext<E>>,
    pub proof: ShuffleProof<E>
}

#[derive(Serialize, Deserialize)]
pub struct PartialDecryption<E: Element> {
    pub partially_decrypted_ballots: Vec<Ciphertext<E>>,
    pub proofs: Vec<ChaumPedersen<E>>
}

#[cfg(test)]
mod tests {  
    use uuid::Uuid;
    use crate::rug_b::*;
    use crate::artifact::*;
    use rand_core::OsRng;
    use ed25519_dalek::Keypair;


    #[test]
    fn test_config_serde() {
        let mut csprng = OsRng;
        let id = Uuid::new_v4();
        let group = RugGroup::default();
        let contests = 2;
        let ballotbox_pk = Keypair::generate(&mut csprng).public; 
        let trustees = 3;
        let mut trustee_pks = Vec::with_capacity(trustees);
        
        for _ in 0..trustees {
            let keypair = Keypair::generate(&mut csprng);
            trustee_pks.push(keypair.public);
        }
        let cfg = Config {
            id: id.as_bytes().clone(), 
            generator: Some(group.generator),
            modulus: Some(group.modulus),
            modulus_exp: Some(group.modulus_exp),
            contests: contests, 
            ballotbox: ballotbox_pk, 
            trustees: trustee_pks
        };

        let cfg_b = bincode::serialize(&cfg).unwrap();
        let cfg_d: Config = bincode::deserialize(&cfg_b).unwrap();

        assert_eq!(cfg, cfg_d);
    }
}