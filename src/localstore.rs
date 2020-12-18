use std::path::{Path,PathBuf};
use std::marker::PhantomData;
use base64::{encode, decode};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::hashing;
use crate::protocol;
use crate::util;
use crate::action::Act;
use crate::artifact::*;
use crate::elgamal::PublicKey;
use crate::arithm::Element;
use crate::group::Group;

pub struct ConfigPath(pub PathBuf);
pub struct ConfigStmtPath(pub PathBuf);
pub struct KeysharePath(pub PathBuf, pub PathBuf);
pub struct PkPath(pub PathBuf, pub PathBuf);
pub struct PkStmtPath(pub PathBuf);

pub struct LocalStore<E: Element, G: Group<E>> {
    pub fs_path: PathBuf,
    phantom_e: PhantomData<E>,
    phantom_g: PhantomData<G>
}

impl<E: Element + Serialize + DeserializeOwned, 
    G: Group<E> + Serialize + DeserializeOwned> 
    LocalStore<E, G> {
    
    pub fn new(fs_path: String) -> LocalStore<E, G> {
        let target = Path::new(&fs_path);
        assert!(target.exists() && target.is_dir());
        LocalStore {
            fs_path: target.to_path_buf(),
            phantom_e: PhantomData,
            phantom_g: PhantomData
        }
    }
    
    pub fn set_config(&self, config: &Config<E, G>) -> ConfigPath {
        let cfg_b = bincode::serialize(&config).unwrap();
        ConfigPath (
            self.set_work(&Act::AddConfig, vec![cfg_b]).remove(0)
        )
    }
    pub fn set_config_stmt(&self, act: &Act, stmt: &SignedStatement) -> ConfigStmtPath {
        assert!(matches!(act, Act::CheckConfig(_)));
        assert!(matches!(stmt.statement.stype, StatementType::Config));
        let stmt_b = bincode::serialize(&stmt).unwrap();
        ConfigStmtPath (
            self.set_work(act, vec![stmt_b]).remove(0)
        )
    }
    pub fn set_share(&self, act: &Act, share: Keyshare<E, G>, stmt: &SignedStatement) -> KeysharePath {
        assert!(matches!(act, Act::PostShare(..)));
        assert!(matches!(stmt.statement.stype, StatementType::Keyshare));
        let share_b = bincode::serialize(&share).unwrap();
        let stmt_b = bincode::serialize(&stmt).unwrap();
        let mut paths = self.set_work(act, vec![share_b, stmt_b]);
        let share_p = paths.remove(0);
        let stmt_p = paths.remove(0);
        
        KeysharePath (share_p, stmt_p)
    }
    pub fn set_pk(&self, act: &Act, pk: PublicKey<E, G>, stmt: &SignedStatement) -> PkPath {
        assert!(matches!(act, Act::CombineShares(..)));
        assert!(matches!(stmt.statement.stype, StatementType::PublicKey));
        let pk_b = bincode::serialize(&pk).unwrap();
        let stmt_b = bincode::serialize(&stmt).unwrap();
        let mut paths = self.set_work(act, vec![pk_b, stmt_b]);
        let pk_p = paths.remove(0);
        let stmt_p = paths.remove(0);
        
        PkPath(pk_p, stmt_p)
    }
    pub fn set_pk_stmt(&self, act: &Act, stmt: &SignedStatement) -> PkStmtPath {
        assert!(matches!(act, Act::CheckPk(..)));
        assert!(matches!(stmt.statement.stype, StatementType::PublicKey));
        let stmt_b = bincode::serialize(&stmt).unwrap();
        let mut paths = self.set_work(act, vec![stmt_b]);
        let stmt_p = paths.remove(0);
        
        PkStmtPath(stmt_p)
    }
    
    pub fn get_work(&self, action: &Act, hash: hashing::Hash) -> Option<Vec<PathBuf>> {
        let target = self.path_for_action(action);
        let mut ret = Vec::new();
        for i in 0..10 {
            let with_ext = target.with_extension(i.to_string());
            if with_ext.exists() && with_ext.is_file() {
                ret.push(with_ext);
            }
            else {
                break;
            }
        }

        if ret.len() > 0 {
            Some(ret)
        }
        else {
            None
        }
    }

    fn set_work(&self, action: &Act, work: Vec<Vec<u8>>) -> Vec<PathBuf> {
        let target = self.path_for_action(action);
        let mut ret = Vec::new();
        
        for (i, item) in work.iter().enumerate() {
            let with_ext = target.with_extension(i.to_string());
            assert!(!with_ext.exists());
            util::write_file_bytes(&with_ext, item).unwrap();
            ret.push(with_ext);
        }
        ret
    }
    
    fn path_for_action(&self, action: &Act) -> PathBuf {
        let hash = hashing::hash(action);
        let encoded = hex::encode(&hash);
        let work_path = Path::new(&encoded);
        let ret = Path::new(&self.fs_path).join(work_path);
        // println!("action {:?}, returning path {:?}", action, ret);

        ret
    }
}

