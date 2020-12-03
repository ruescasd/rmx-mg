use ed25519_dalek::PublicKey as SignaturePublicKey;
// use curve25519_dalek::ristretto::{RistrettoPoint};
use serde::{Deserialize, Serialize};

use crate::arithm::*;
use crate::elgamal::*;
use crate::group::*;
use crate::shuffler::*;
use crate::rug_b::RugGroup;

type Hash = Vec<u8>;

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct Statement(String, u32, Vec<Hash>);

impl Statement {
    pub fn config(config: Hash, item: u32) -> Statement {
        Statement(
            "config".to_string(),
            item,
            vec![config]
        )
    }
    pub fn keyshare(config: Hash, item: u32, share: Hash) -> Statement {
        Statement(
            "keyshare".to_string(),
            item,
            vec![config, share]
        )
    }
    pub fn public_key(config: Hash, item: u32, public_key: Hash) -> Statement {
        Statement(
            "public_key".to_string(),
            item,
            vec![config, public_key]
        )
    }
    pub fn ballots(config: Hash, item: u32, ballots: Hash) -> Statement {
        Statement(
            "ballots".to_string(),
            item,
            vec![config, ballots]
        )
    }
    pub fn mix(config: Hash, item: u32, mix: Hash, ballots: Hash) -> Statement {
        Statement(
            "mix".to_string(),
            item,
            vec![config, mix, ballots]
        )
    }
    pub fn partial_decryption(config: Hash, item: u32, partial_decryptions: Hash, ballots: Hash) -> Statement {
        Statement(
            "partial_decryption".to_string(),
            item,
            vec![config, partial_decryptions, ballots]
        )
    }
    pub fn plaintexts(config: Hash, item: u32, plaintexts: Hash, partial_decryptions: Hash) -> Statement {
        Statement(
            "plaintexts".to_string(),
            item,
            vec![config, plaintexts, partial_decryptions]
        )
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct Config {
    pub id: [u8; 16],
    pub rug_group: Option<RugGroup>,
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
pub struct EncryptedPrivateKey {
    pub bytes: Vec<u8>,
    pub iv: Vec<u8>
}

#[derive(Serialize, Deserialize)]
pub struct Pk<E: Element, G: Group<E>> {
    pub value: PublicKey<E, G>,
}

#[derive(Serialize, Deserialize)]
pub struct Ballots<E: Element> {
    pub ciphertexts: Vec<Ciphertext<E>>
}

#[derive(Serialize, Deserialize)]
pub struct Mix<E: Element> {
    pub mixed_ballots: Vec<Ciphertext<E>>,
    pub proof: ShuffleProof<E>
}

#[derive(Serialize, Deserialize)]
pub struct PartialDecryption<E: Element> {
    pub pd_ballots: Vec<E>,
    pub proofs: Vec<ChaumPedersen<E>>
}

#[derive(Serialize, Deserialize)]
pub struct Plaintexts<E> {
    plaintexts: Vec<E>
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
            rug_group: Some(group),
            contests: contests, 
            ballotbox: ballotbox_pk, 
            trustees: trustee_pks
        };

        let cfg_b = bincode::serialize(&cfg).unwrap();
        let cfg_d: Config = bincode::deserialize(&cfg_b).unwrap();

        assert_eq!(cfg, cfg_d);
    }
}