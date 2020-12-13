use crate::hashing;
use crate::protocol;
use crate::util;
use std::path::{Path,PathBuf};
use base64::{encode, decode};


struct LocalStore {
    pub fs_path: String
}

impl LocalStore {
    pub fn get_work(&self, action: &protocol::Act, hash: hashing::Hash) -> Option<PathBuf> {
        let target = self.path_for_action(action);
        if target.exists() && target.is_file() {
            Some(target.to_path_buf())
        }
        else {
            None
        }
    }
    pub fn set_work(&self, action: &protocol::Act, work: Vec<u8>) {
        let target = self.path_for_action(action);
        assert!(!target.exists());
        util::write_file_bytes(&target, work).unwrap()
    }
    fn path_for_action(&self, action: &protocol::Act) -> PathBuf {
        let hash = hashing::hash(action);
        let base64 = encode(&hash);
        let work_path = Path::new(&base64);
        Path::new(&self.fs_path).join(work_path)
    }
}

