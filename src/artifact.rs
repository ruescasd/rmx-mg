use ed25519_dalek::PublicKey as SignaturePublicKey;
use curve25519_dalek::ristretto::{RistrettoPoint};
use serde::{Deserialize, Serialize};

use crate::arithm::*;
use crate::elgamal::*;
use crate::group::*;
use crate::shuffler::*;
use crate::rug_b::RugGroup;

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct Config {
    pub id: [u8; 16],
    pub rug_group: Option<RugGroup>,
    pub contests: u32, 
    pub ballotbox: SignaturePublicKey, 
    pub trustees: Vec<SignaturePublicKey>
}

#[derive(Serialize, Deserialize)]
pub struct ConfigStatement {
    _stmt: [u8; 6],
    pub config_hash: Vec<u8>
}
impl ConfigStatement {
    fn new(config_hash: Vec<u8>) -> ConfigStatement {
        ConfigStatement {
            _stmt: *b"config",
            config_hash: config_hash
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Keyshare<E: Element, G: Group<E>> {
    pub share: PublicKey<E, G>,
    pub proof: Schnorr<E>
}
#[derive(Serialize, Deserialize)]
pub struct KeyshareStatement {
    _stmt: [u8; 8],
    pub config_hash: Vec<u8>,
    pub keyshare_hash: Vec<u8>
}
impl KeyshareStatement {
    fn new(config_hash: Vec<u8>, keyshare_hash: Vec<u8>) -> KeyshareStatement {
        KeyshareStatement {
            _stmt: *b"keyshare",
            config_hash: config_hash,
            keyshare_hash: keyshare_hash
        }
    }
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
pub struct PkStatement {
    _stmt: [u8; 2],
    pub config_hash: Vec<u8>,
    pub public_key_hash: Vec<u8>
}
impl PkStatement {
    fn new(config_hash: Vec<u8>, public_key_hash: Vec<u8>) -> PkStatement {
        PkStatement {
            _stmt: *b"pk",
            config_hash: config_hash,
            public_key_hash: public_key_hash
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Ballots<E: Element> {
    pub ciphertexts: Vec<Ciphertext<E>>
}
#[derive(Serialize, Deserialize)]
pub struct BallotsStatement {
    _stmt: [u8; 7],
    pub config_hash: Vec<u8>,
    pub ballots_hash: Vec<u8>
}
impl BallotsStatement {
    fn new(config_hash: Vec<u8>, ballots_hash: Vec<u8>) -> BallotsStatement {
        BallotsStatement {
            _stmt: *b"ballots",
            config_hash: config_hash,
            ballots_hash: ballots_hash
        }
    }
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