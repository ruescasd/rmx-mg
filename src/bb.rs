use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::path::Path;

use crate::hashing::{HashBytes, Hash};
use crate::hashing;

pub trait BulletinBoard<E> {
    fn refresh(&self) -> Result<(), E>;
    fn post(&self, files: Vec<(&Path, &Path)>, message: &str) -> Result<(), E>;
    fn list(&self) -> Vec<String>;
    fn get<A: HashBytes + DeserializeOwned>(&self, key: String, hash: Hash) -> 
        Result<A, bincode::Error>;
}

pub struct MemoryBulletinBoard(pub HashMap<String, Vec<u8>>);

impl MemoryBulletinBoard {
    pub fn new() -> MemoryBulletinBoard {
        MemoryBulletinBoard(HashMap::new())
    }
    pub fn add(&mut self, key: String, value: Vec<u8>) {
        self.0.insert(key, value);
    }
}

impl BulletinBoard<&'static str> for MemoryBulletinBoard {
    fn refresh(&self) -> Result<(), &'static str> {
        Ok(())
    }
    fn post(&self, files: Vec<(&Path, &Path)>, message: &str) -> Result<(), &'static str> {
        Ok(())
    }
    fn list(&self) -> Vec<String> {
        self.0.iter().map(|(a, _)| a.clone()).collect()
    }
    fn get<A: HashBytes + DeserializeOwned>(&self, key: String, hash: Hash) -> Result<A, bincode::Error> {
        let bytes = self.0.get(&key)
            .ok_or(bincode::ErrorKind::Custom("not found".to_string()))?;

        let artifact = bincode::deserialize::<A>(bytes)?;

        let hashed = hashing::hash(&artifact);
        
        if hashed == hash {
            Ok(artifact)
        }
        else {
            Err(Box::new(bincode::ErrorKind::Custom("Mismatched hash".to_string())))
        }
    }
}

pub trait Names {
    const CONFIG: &'static str = "config.json";
    const CONFIG_STMT: &'static str = "config.stmt.json";
    const PAUSE: &'static str = "pause";
    const ERROR: &'static str = "error";

    fn config_sig(auth: u32) -> String { format!("{}/config.sig", auth).to_string() }

    fn share(contest: u32, auth: u32) -> String { format!("{}/{}/share", auth, contest).to_string() }
    fn share_stmt(contest: u32, auth: u32) -> String { format!("{}/{}/share.stmt", auth, contest).to_string() }
    fn share_sig(contest: u32, auth: u32) -> String { format!("{}/{}/share.sig", auth, contest).to_string() }

    fn public_key(contest: u32, auth: u32) -> String { format!("{}/{}/public_key", auth, contest).to_string() }
    fn public_key_stmt(contest: u32, auth: u32) -> String { format!("{}/{}/public_key.stmt", auth, contest).to_string() }
    fn public_key_sig(contest: u32, auth: u32) -> String { format!("{}/{}/public_key.sig", auth, contest).to_string() }

    fn ballots(contest: u32) -> String { format!("{}/ballots", contest).to_string() }
    fn ballots_stmt(contest: u32) -> String { format!("{}/ballots_stmt", contest).to_string() }
    fn ballots_sig(contest: u32) -> String { format!("{}/ballots_sig", contest).to_string() }
    
    fn mix(contest: u32, auth: u32) -> String { format!("{}/{}/mix", auth, contest).to_string() }
    fn mix_stmt(contest: u32, auth: u32) -> String { format!("{}/{}/mix.stmt", auth, contest).to_string() }
    fn mix_sig(contest: u32, auth: u32, signing_auth: u32) -> String { format!("{}/{}/mix.{}.sig", signing_auth, contest, auth).to_string() }

    fn decryption(contest: u32, auth: u32) -> String { format!("{}/{}/decryption", auth, contest).to_string() }
    fn decryption_stmt(contest: u32, auth: u32) -> String { format!("{}/{}/decryption.stmt", auth, contest).to_string() }
    fn decryption_sig(contest: u32, auth: u32) -> String { format!("{}/{}/decryption.sig", auth, contest).to_string() }

    fn plaintexts(contest: u32, auth: u32) -> String { format!("{}/{}/plaintexts", auth, contest).to_string() }
    fn plaintexts_stmt(contest: u32, auth: u32) -> String { format!("{}/{}/plaintexts.stmt", auth, contest).to_string() }
    fn plaintexts_sig(contest: u32, auth: u32) -> String { format!("{}/{}/plaintexts.sig", auth, contest).to_string() }
    
    fn auth_error(auth: u32) -> String { format!("{}/error", auth).to_string() }
}

#[cfg(test)]
mod tests {

    use crate::hashing;
    use crate::bb;
    use crate::bb::BulletinBoard;
    use crate::artifact;
    use uuid::Uuid;
    use crate::rug_b::*;
    use rand_core::OsRng;
    use ed25519_dalek::Keypair;
        
    #[test]
    fn test_membb_get() {
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
        let mut cfg = artifact::Config {
            id: id.as_bytes().clone(),
            rug_group: Some(group),
            contests: contests, 
            ballotbox: ballotbox_pk, 
            trustees: trustee_pks
        };

        let mut bb = bb::MemoryBulletinBoard::new();
        let cfg_b = bincode::serialize(&cfg).unwrap();
        let hash = hashing::hash(&cfg);
        bb.add("hello".to_string(), cfg_b);
        let mut cfg_result = bb.get::<artifact::Config>("hello".to_string(), hash);
        assert!(cfg_result.is_ok());

        cfg.id = Uuid::new_v4().as_bytes().clone();
        let bad_hash = hashing::hash(&cfg);
        cfg_result = bb.get::<artifact::Config>("hello".to_string(), bad_hash);
        assert!(cfg_result.is_err());
    }
}