use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::path::Path;
use std::fs;

use crate::hashing::{HashBytes, Hash};
use crate::hashing;
use crate::bb::*;
use crate::artifact::*;
use crate::protocol::SVerifier;
use crate::arithm::Element;
use crate::group::Group;
use crate::util;
use crate::localstore::*;

pub struct MemoryBulletinBoard<E: Element + DeserializeOwned, G: Group<E> + DeserializeOwned> {
    data: HashMap<String, Vec<u8>>,
    bogus: Option<E>,
    bogus2: Option<G>
}
impl<E: Element + DeserializeOwned, G: Group<E> + DeserializeOwned> Names for MemoryBulletinBoard
<E, G>{}

impl<E: Element + DeserializeOwned, G: Group<E> + DeserializeOwned> MemoryBulletinBoard<E, G> {
    pub fn new() -> MemoryBulletinBoard<E, G> {
        MemoryBulletinBoard {
            data: HashMap::new(),
            bogus: None,
            bogus2: None
        }
    }
    fn put(&mut self, name: &str, data: &Path) {
        let bytes = util::read_file_bytes(data).unwrap();
        self.data.insert(name.to_string(), bytes);
    }
   
    fn get<A: HashBytes + DeserializeOwned>(&self, target: String, hash: Hash) -> Result<A, String> {
        let key = target;
        let bytes = self.data.get(&key).ok_or("Not found")?;

        let artifact = bincode::deserialize::<A>(bytes)
            .map_err(|e| std::format!("serde error {}", e))?;

        let hashed = hashing::hash(&artifact);
        
        if hashed == hash {
            Ok(artifact)
        }
        else {
            Err("Hash mismatch".to_string())
        }
    }
    
}


impl<E: Element + DeserializeOwned, G: Group<E> + DeserializeOwned> 
    BulletinBoard<E, G> for MemoryBulletinBoard<E, G> {
    
    fn get_config_unsafe(&self) -> Option<Config> {
        let bytes = self.data.get(Self::CONFIG)?;
        let ret: Config = bincode::deserialize(bytes).unwrap();

        Some(ret)
    }
    fn get_config(&self, hash: Hash) -> Option<Config> {
        let ret = self.get(Self::CONFIG.to_string(), hash).ok()?;

        Some(ret)
    }
    fn add_config(&mut self, path: &ConfigPath) {
        self.put(Self::CONFIG, &path.0);
    }
    fn add_config_stmt(&mut self, path: &ConfigStmtPath, trustee: u32) {
        self.put(&Self::config_stmt(trustee), &path.0);
    }
    fn add_share(&mut self, path: &KeysharePath, contest: u32, trustee: u32) {
        self.put(&Self::share(contest, trustee), &path.0);
        self.put(&Self::share_stmt(contest, trustee), &path.1);
    }
    fn get_share(&self, contest: u32, auth: u32, hash: Hash) -> Option<Keyshare<E, G>> {
        let key = Self::share(contest, auth).to_string();
        let ret = self.get(key, hash).ok()?;
        // let bytes = self.data.get(&Self::share(contest, auth))?;
        // let ret: Keyshare<E, G> = bincode::deserialize(bytes).unwrap();

        Some(ret)
    }
    fn set_pk(&mut self, path: &PkPath, contest: u32) {
        // 0: trustee 0 combines shares into pk
        self.put(&Self::public_key(contest, 0), &path.0);
        self.put(&Self::public_key_stmt(contest, 0), &path.1);
    }
    fn set_pk_stmt(&mut self, path: &PkStmtPath, contest: u32, trustee: u32) {
        self.put(&Self::public_key_stmt(contest, trustee), &path.0);
    }

    fn list(&self) -> Vec<String> {
        self.data.iter().map(|(a, _)| a.clone()).collect()
    }
    fn get_statements(&self) -> Vec<SVerifier> {
        
        let sts = self.get_stmts();
        let mut ret = Vec::new();
        println!("Statements {:?}", sts);
        
        for s in sts.iter() {
            
            let s_bytes = self.data.get(s).unwrap().to_vec();
            let (trustee, contest) = artifact_location(s);
            let stmt: SignedStatement = bincode::deserialize(&s_bytes).unwrap();

            let next = SVerifier {
                statement: stmt,
                trustee: trustee,
                contest: contest
            };
            ret.push(next);
        }

        ret
    }
}

fn artifact_location(path: &str) -> (u32, u32) {
    let p = Path::new(&path);
    let comp: Vec<&str> = p.components()
        .take(2)
        .map(|comp| comp.as_os_str().to_str().unwrap())
        .collect();
    
    let auth: u32 = comp[0].parse().unwrap_or(0);
    let contest: u32 = comp[1].parse().unwrap_or(0);

    (auth, contest)
}

#[cfg(test)]
mod tests {

    use uuid::Uuid;
    
    use rand_core::OsRng;
    use ed25519_dalek::Keypair;
    use tempfile::NamedTempFile;
    use std::path::Path;
    use rug::Integer;

    use crate::hashing;
    use crate::artifact;
    use crate::rug_b::*;
    use crate::memory_bb::*;
        
    #[test]
    fn test_membb_putget() {
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

        let mut bb = MemoryBulletinBoard::<Integer, RugGroup>::new();
        let cfg_b = bincode::serialize(&cfg).unwrap();
        
        let tmp_file = NamedTempFile::new().unwrap();
        let target = "test";
        let path = tmp_file.path();
        std::fs::write(path, &cfg_b).unwrap();
        bb.put("test", path);
        
        let hash = hashing::hash(&cfg);
        let mut cfg_result = bb.get::<artifact::Config>(target.to_string(), hash);
        assert!(cfg_result.is_ok());

        cfg.id = Uuid::new_v4().as_bytes().clone();
        let bad_hash = hashing::hash(&cfg);
        cfg_result = bb.get::<artifact::Config>(target.to_string(), bad_hash);
        assert!(cfg_result.is_err());
    }
}