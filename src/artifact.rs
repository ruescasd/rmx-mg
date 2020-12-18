use std::marker::PhantomData;

use ed25519_dalek::PublicKey as SPublicKey;
use ed25519_dalek::Signature;
use ed25519_dalek::{Keypair, Signer};
use serde::{Deserialize, Serialize};
use crepe::crepe;

use crate::arithm::*;
use crate::elgamal::*;
use crate::group::*;
use crate::shuffler::*;
use crate::bb::*;
use crate::rug_b::RugGroup;
use crate::ristretto_b::RistrettoGroup;
use crate::hashing;
use crate::protocol::ContestIndex;
use rug::Integer;
use curve25519_dalek::ristretto::RistrettoPoint;

type Hash = Vec<u8>;

/*#[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct Config {
    pub id: [u8; 16],
    pub rug_group: Option<RugGroup>,
    pub contests: u32, 
    pub ballotbox: SPublicKey, 
    pub trustees: Vec<SPublicKey>
}*/

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct Config<E: Element, G: Group<E>> {
    pub id: [u8; 16],
    pub group: G,
    pub contests: u32, 
    pub ballotbox: SPublicKey, 
    pub trustees: Vec<SPublicKey>,
    pub phantom_e: PhantomData<E>
}

/*impl Config {
    pub fn get_group<Integer>(&self) -> Group<Integer> {
        self.rug_group.unwrap()
    }
    pub fn get_groups<RistrettoPoint>(&self) -> Group<RistrettoPoint> {
        RistrettoGroup
    }
}*/

#[derive(Serialize, Deserialize)]
pub struct Keyshare<E: Element, G: Group<E>> {
    pub share: PublicKey<E, G>,
    pub proof: Schnorr<E>,
    pub encrypted_sk: EncryptedPrivateKey
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
    pub plaintexts: Vec<E>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignedStatement {
    pub statement: Statement, 
    pub signature: Signature
}

impl SignedStatement {
    pub fn config(cfg_h: &hashing::Hash, pk: &Keypair) -> SignedStatement {
        let statement = Statement::config(cfg_h.to_vec());
        let stmt_h = hashing::hash(&statement);
        let signature = pk.sign(&stmt_h);
        SignedStatement {
            statement,
            signature
        }
    }
    pub fn keyshare(cfg_h: &hashing::Hash, share_h: &hashing::Hash, contest: u32, pk: &Keypair) -> SignedStatement {
        let statement = Statement::keyshare(cfg_h.to_vec(), contest, share_h.to_vec());
        let stmt_h = hashing::hash(&statement);
        let signature = pk.sign(&stmt_h);
        SignedStatement {
            statement,
            signature
        }
    }
    pub fn public_key(cfg_h: &hashing::Hash, pk_h: hashing::Hash, contest: u32, pk: &Keypair) -> SignedStatement {
        let statement = Statement::public_key(cfg_h.to_vec(), contest, pk_h.to_vec());
        let stmt_h = hashing::hash(&statement);
        let signature = pk.sign(&stmt_h);
        SignedStatement {
            statement,
            signature
        }
    }
}

#[repr(u8)]
#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone, Copy)]
pub enum StatementType {
    Config,
    Keyshare,
    PublicKey,
    Ballots,
    Mix,
    PDecryption,
    Plaintexts
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct Statement {
    pub stype: StatementType, 
    pub contest: ContestIndex, 
    pub hashes: Vec<Hash>
}

impl Statement {
    pub fn config(config: Hash) -> Statement {
        Statement {
            stype: StatementType::Config,
            contest: 0,
            hashes: vec![config]
        }
    }
    pub fn keyshare(config: Hash, contest: u32, share: Hash) -> Statement {
        Statement {
            stype: StatementType::Keyshare,
            contest: contest,
            hashes: vec![config, share]
        }
    }
    pub fn public_key(config: Hash, contest: u32, public_key: Hash) -> Statement {
        Statement {
            stype: StatementType::PublicKey,
            contest: contest,
            hashes: vec![config, public_key]
        }
    }
    pub fn ballots(config: Hash, contest: u32, ballots: Hash) -> Statement {
        Statement {
            stype: StatementType::Ballots,
            contest: contest,
            hashes: vec![config, ballots]
        }
    }
    pub fn mix(config: Hash, contest: u32, mix: Hash, ballots: Hash) -> Statement {
        Statement {
            stype: StatementType::Mix,
            contest: contest,
            hashes: vec![config, mix, ballots]
        }
    }
    pub fn partial_decryption(config: Hash, contest: u32, partial_decryptions: Hash, ballots: Hash) -> Statement {
        Statement {
            stype: StatementType::PDecryption,
            contest: contest,
            hashes: vec![config, partial_decryptions, ballots]
        }
    }
    pub fn plaintexts(config: Hash, contest: u32, plaintexts: Hash, partial_decryptions: Hash) -> Statement {
        Statement {
            stype: StatementType::Plaintexts,
            contest: contest,
            hashes: vec![config, plaintexts, partial_decryptions]
        }
    }
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
            group: group,
            contests: contests, 
            ballotbox: ballotbox_pk, 
            trustees: trustee_pks,
            phantom_e: PhantomData
        };

        let cfg_b = bincode::serialize(&cfg).unwrap();
        let cfg_d: Config<Integer, RugGroup> = bincode::deserialize(&cfg_b).unwrap();

        assert_eq!(cfg, cfg_d);
    }
}