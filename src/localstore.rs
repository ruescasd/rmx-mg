use std::path::{Path,PathBuf};
use base64::{encode, decode};

use crate::hashing;
use crate::protocol;
use crate::util;
use crate::action::Act;



pub struct LocalStore {
    pub fs_path: PathBuf
}

impl LocalStore {
    pub fn new(fs_path: String) -> LocalStore {
        let target = Path::new(&fs_path);
        assert!(target.exists() && target.is_dir());
        LocalStore {
            fs_path: target.to_path_buf()
        }
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
    pub fn set_work(&self, action: &Act, work: Vec<Vec<u8>>) -> Vec<PathBuf> {
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
        Path::new(&self.fs_path).join(work_path)
    }
}

