use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::path::Path;
use std::fs;

use crate::hashing::{HashBytes, Hash};
use crate::hashing;
use crate::bb::*;
use crate::artifact::*;
use crate::protocol::StatementV;
use crate::arithm::Element;
use crate::group::Group;

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
        let bytes = fs::read(data).unwrap();
        self.data.insert(name.to_string(), bytes);
    }
   
    fn get<A: HashBytes + DeserializeOwned>(&self, target: &Path, hash: Hash) -> Result<A, String> {
        let key = target.to_str().unwrap().to_string();
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
    
    fn get_config(&self) -> Option<Config> {
        let bytes = self.data.get(Self::CONFIG)?;
        let ret: Config = bincode::deserialize(bytes).unwrap();

        Some(ret)
    }
    fn add_config(&mut self, config: &Path, stmt: &Path) {
        self.put(Self::CONFIG, config);
    }
    fn add_config_sig(&mut self, sig: &Path, trustee: u32) {
        self.put(&Self::config_sig(trustee), sig);
    }
    fn get_share(&self, contest: u32, auth: u32) -> Option<Keyshare<E, G>> {
        let bytes = self.data.get(&Self::share(contest, auth))?;
        let ret: Keyshare<E, G> = bincode::deserialize(bytes).unwrap();

        Some(ret)
    }
    fn list(&self) -> Vec<String> {
        self.data.iter().map(|(a, _)| a.clone()).collect()
    }
    fn get_statements(&self) -> Vec<StatementV> {
        
        let sts = self.get_stmts();
        sts.iter().map(|s| {
            
            let s_bytes = self.data.get(s).unwrap().to_vec();
            let sig_bytes = self.data.get(&s.replace(".stmt", ".sig")).unwrap().to_vec();
            let (trustee, contest) = artifact_location(s);

            let stmt = bincode::deserialize(&s_bytes).unwrap();
            let stmt_hash = hashing::hash(&stmt);
            let sig = bincode::deserialize(&sig_bytes).unwrap();

            StatementV {
                statement: stmt,
                signature: sig,
                statement_hash: stmt_hash,
                trustee: trustee,
                contest: contest
            }
            
        }).collect()
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
        let target = Path::new("test");
        let path = tmp_file.path();
        std::fs::write(path, &cfg_b).unwrap();
        bb.put("test", path);
        
        let hash = hashing::hash(&cfg);
        let mut cfg_result = bb.get::<artifact::Config>(target, hash);
        assert!(cfg_result.is_ok());

        cfg.id = Uuid::new_v4().as_bytes().clone();
        let bad_hash = hashing::hash(&cfg);
        cfg_result = bb.get::<artifact::Config>(target, bad_hash);
        assert!(cfg_result.is_err());
    }
}