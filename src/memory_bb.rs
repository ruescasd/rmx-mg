use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::path::Path;
use std::fs;

use crate::hashing::{HashBytes, Hash};
use crate::hashing;
use crate::bb::*;
use crate::artifact::*;

pub struct MemoryBulletinBoard {
    data: HashMap<String, Vec<u8>>
}
impl Names for MemoryBulletinBoard{}

impl MemoryBulletinBoard {
    pub fn new() -> MemoryBulletinBoard {
        MemoryBulletinBoard {
            data: HashMap::new()
        }
    }
    fn put(&mut self, name: &str, data: &Path) {
        let bytes = fs::read(data).unwrap();
        self.data.insert(name.to_string(), bytes);
    }
    fn list(&self) -> Vec<String> {
        self.data.iter().map(|(a, _)| a.clone()).collect()
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
    fn get_statements(&self) -> Vec<String> {
        self.list().into_iter().filter(|s| {
            s.ends_with(".stmt")
        }).collect()
    }
    fn get_statement_triples(&self) -> Vec<StatementData> {
        
        let sts = self.get_statements();
        sts.iter().map(|s| {
            
            let s_bytes = self.data.get(s).unwrap().to_vec();
            let (trustee, contest) = artifact_location(s);

            let stmt = bincode::deserialize(&s_bytes).unwrap();

            StatementData {
                statement: stmt,
                trustee: trustee,
                contest: contest
            }
            
        }).collect()
    }
}

impl BulletinBoard for MemoryBulletinBoard {
    fn add_config(&mut self, config: &Path) {
        self.put(Self::CONFIG, config);
    }
    fn get_config(&self) -> Option<Config> {
        let bytes = self.data.get(Self::CONFIG)?;
        let ret: Config = bincode::deserialize(bytes).unwrap();

        Some(ret)
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

        let mut bb = MemoryBulletinBoard::new();
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