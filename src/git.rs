use std::path::{Path, PathBuf};
use std::fs;

use git2::build::{CheckoutBuilder, RepoBuilder};
use git2::*;
use tempfile::NamedTempFile;
use walkdir::{DirEntry, WalkDir};

use serde::{Deserialize, Serialize};

use crate::util;

#[derive(Serialize, Deserialize)]
struct GitBulletinBoard {
    pub ssh_key_path: String,
    pub url: String,
    pub fs_path: String,
    pub append_only: bool
}


impl GitBulletinBoard {
    
    pub fn refresh(&self) -> Result<(), git2::Error> {
        let repo = self.open_or_clone()?;
        let mut remote = repo.find_remote("origin").unwrap();
        let mut fo = FetchOptions::new();
        let cb = remote_callbacks(&self.ssh_key_path);
        fo.remote_callbacks(cb);
        fo.download_tags(git2::AutotagOption::All);
        remote.fetch(&["master"], Some(&mut fo), None)?;
    
        let fetch_head = repo.find_reference("FETCH_HEAD")?;
        let commit = repo.reference_to_annotated_commit(&fetch_head)?;
        
        let head = repo.head()?;
        let local_commit = repo.reference_to_annotated_commit(&head)?;
        let local_object = repo.find_object(local_commit.id(), None)?;
        repo.reset(&local_object, git2::ResetType::Hard, None)?;
        
        let analysis = repo.merge_analysis(&[&commit])?;
    
        if analysis.0.is_up_to_date() {
            println!("Up to date");
            Ok(())
        }
        else if analysis.0.is_fast_forward() {        
            println!("Requires fast-forward");
            if self.append_only {
                let mut opts = DiffOptions::new();
                let tree_old = repo.find_commit(local_commit.id()).unwrap().tree().unwrap();
                let tree_new = repo.find_commit(commit.id()).unwrap().tree().unwrap();
                
                let diff = repo.diff_tree_to_tree(Some(&tree_old), Some(&tree_new), Some(&mut opts))?;
                for d in diff.deltas() {
                    if d.status() != Delta::Added {
                        return Err(git2::Error::from_str(&format!("Found non-add git delta in append-only mode: {:?}", d)))
                    }
                }
            }
            
            let refname = format!("refs/heads/master");
            let mut r = repo.find_reference(&refname)?;
            fast_forward(&repo, &mut r, &commit)?;
            Ok(())
        }
        else {
            // Err(git2::Error::from_str("Unexpected merge required"))
            panic!("Unexpected merge required");
        }
    }

    pub fn post(&self, files: Vec<(&str, &Path)>, message: &str) -> Result<(), git2::Error> {
        let repo = self.open_or_clone()?;
        self.reset(&repo)?;
        self.add_commit_many(&repo, files, message, self.append_only)?;
        self.push(&repo)
    }

    pub fn list(&self) -> Vec<String> {
        let walker = WalkDir::new(&self.fs_path).min_depth(1).into_iter();
        let entries: Vec<DirEntry> = walker
            .filter_entry(|e| !is_hidden(e))
            .map(|e| e.unwrap())
            .collect();
         
        // filter directories and make relative
        let files = entries.into_iter()
            .filter(|e| !e.file_type().is_dir())
            .map(|e| {
                e.path()
                    .strip_prefix(&self.fs_path).unwrap()
                    .to_str().unwrap().to_string()
            })
            .collect();

        files
    }

    fn open_or_clone(&self) -> Result<Repository, Error> {    
        if Path::new(&self.fs_path).exists() {
            Repository::open(&self.fs_path)
        }
        else {  
            let co = CheckoutBuilder::new();
            let mut fo = FetchOptions::new();
            let cb = remote_callbacks(&self.ssh_key_path);
            fo.remote_callbacks(cb);    
            RepoBuilder::new()
                .fetch_options(fo)
                .with_checkout(co)
                .clone(&self.url, Path::new(&self.fs_path))
        }
    }

    fn add_to_working_copy(&self, target: &str, source: &Path) -> PathBuf {
        let target_path = Path::new(target);
        let target_file = Path::new(&self.fs_path).join(target_path);
        if target_file.is_file() && target_file.exists() {
            fs::remove_file(&target_file).unwrap();
        }
        let tmp_file = NamedTempFile::new().unwrap();
        let tmp_file_path = tmp_file.path();
        fs::copy(source, tmp_file_path).unwrap();
        fs::rename(tmp_file_path, &target_file).unwrap();

        target_path.to_path_buf()
    }
    
    fn add_commit_many(&self, repo: &Repository, files: Vec<(&str, &Path)>, 
        message: &str, append_only: bool) -> Result<Oid, git2::Error> {
        let mut paths = vec![];
        for (target, source) in files {
            let target_path = self.add_to_working_copy(target, source);
            paths.push(target_path);
        }
        // adding to repo index uses relative path
        add_and_commit(&repo, paths, message, append_only)
    }
    
    fn add_commit(&self, repo: &Repository, target: &str, source: &Path, message: &str,
        append_only: bool) -> Result<Oid, git2::Error> {
        
        let target_path = self.add_to_working_copy(target, source);
        // adding to repo index uses relative path: &target_path
        add_and_commit(&repo, [target_path].to_vec(), message, append_only)
    }

    // resets the working copy to match that of the remote
    // local commits and working copy are discarded
    fn reset(&self, repo: &Repository) -> Result<(), git2::Error> {
        let mut remote = repo.find_remote("origin")?;
        let mut fo = FetchOptions::new();
        fo.remote_callbacks(remote_callbacks(&self.ssh_key_path));
        fo.download_tags(git2::AutotagOption::All);
        remote.fetch(&["master"], Some(&mut fo), None)?;
        let fetch_head = repo.find_reference("FETCH_HEAD")?;
        let commit = repo.reference_to_annotated_commit(&fetch_head)?;
        let object = repo.find_object(commit.id(), None)?;
        repo.reset(&object, git2::ResetType::Hard, None)
    }

    fn push(&self, repo: &Repository) -> Result<(), git2::Error> {
        let mut options = PushOptions::new();
        options.remote_callbacks(remote_callbacks(&self.ssh_key_path));
        let mut remote = repo.find_remote("origin").unwrap();
        repo.remote_add_push("origin", "refs/heads/master:refs/heads/master").unwrap();
        remote.connect_auth(Direction::Push, Some(remote_callbacks(&self.ssh_key_path)), None)?;
        remote.push(&["refs/heads/master:refs/heads/master"], Some(&mut options))
    }
}

fn find_last_commit(repo: &Repository) -> Result<Commit, Error> {
    let obj = repo.head()?.resolve()?.peel(ObjectType::Commit)?;
    match obj.into_commit() {
        Ok(c) => Ok(c),
        _ => Err(git2::Error::from_str("Couldn't find commit"))
    }
} 

fn fast_forward(
    repo: &Repository,
    lb: &mut git2::Reference,
    rc: &git2::AnnotatedCommit,
) -> Result<(), git2::Error> {
    let name = match lb.name() {
        Some(s) => s.to_string(),
        None => String::from_utf8_lossy(lb.name_bytes()).to_string(),
    };
    let msg = format!("Fast-Forward: Setting {} to id: {}", name, rc.id());
    println!("{}", msg);
    lb.set_target(rc.id(), &msg)?;
    repo.set_head(&name)?;
    repo.checkout_head(Some(
        git2::build::CheckoutBuilder::default().force()
    ))?;
    Ok(())
}

fn add_and_commit(repo: &Repository, paths: Vec<PathBuf>, message: &str, 
    append_only: bool) -> Result<Oid, git2::Error> {
    
    let mut index = repo.index()?;
    for p in paths {
        index.add_path(&p)?;
    }
    let oid = index.write_tree()?;
    let signature = Signature::now("rmx", "rmx@foo.bar")?;
    let parent_commit = find_last_commit(&repo)?;
    let tree = repo.find_tree(oid)?;
    
    if append_only {
        let mut opts = DiffOptions::new();
        let diff = repo.diff_tree_to_index(Some(&parent_commit.tree()?), Some(&index), Some(&mut opts))?;
        for d in diff.deltas() {
            if d.status() != Delta::Added {
                return Err(git2::Error::from_str(&format!("Found non-add git delta in append-only mode: {:?}", d)))     
            }
        }
    }

    index.write()?;
    repo.commit(Some("HEAD"),
                &signature,
                &signature,
                message,
                &tree,
                &[&parent_commit])
}

fn remote_callbacks<'a>(ssh_path: &'a str) -> RemoteCallbacks<'a> {
    let mut cb = RemoteCallbacks::new();
    let path = Path::new(ssh_path);
    cb.credentials(move |_, _, _| {
        let credentials = 
            Cred::ssh_key(
                "git", 
                None, 
                path,
                None
            ).expect("Could not create credentials object");
    
    
        Ok(credentials)
    });

    cb
}

fn is_hidden(entry: &DirEntry) -> bool {
    entry.file_name()
         .to_str()
         .map(|s| s.starts_with("."))
         .unwrap_or(false)
}

fn read_config() -> GitBulletinBoard {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("resources/test/git_bb.json");
    let cfg = fs::read_to_string(d).unwrap();
    let g: GitBulletinBoard = serde_json::from_str(&cfg).unwrap();

    g
}

#[cfg(test)]
mod tests {
    use serial_test::serial;
    use std::fs;
    use std::path::{Path};
    use crate::git::*;

    
    #[test]
    #[serial]
    fn test_open_or_clone() {
        
        let g = read_config();
        fs::remove_dir_all(&g.fs_path).ok();
        g.open_or_clone().unwrap();
        
        let dir = Path::new(&g.fs_path);
        assert!(dir.exists() && dir.is_dir());
    }

    #[test]
    #[serial]
    fn test_refresh() {
        let g = read_config();
        g.open_or_clone().unwrap();
        
        let dir = Path::new(&g.fs_path);
        assert!(dir.exists() && dir.is_dir());

        g.refresh().unwrap();
    }

    #[test]
    #[serial]
    fn test_post() {
        let g = read_config();
        fs::remove_dir_all(&g.fs_path).ok();
        g.open_or_clone().unwrap();
        let added = util::create_random_file("/tmp");
        let name = added.file_name().unwrap().to_str().unwrap();
        
        g.post(vec![(name, &added)], "new file").unwrap();
        fs::remove_dir_all(&g.fs_path).ok();
        g.open_or_clone().unwrap();
        let files = g.list();
        assert!(files.contains(&name.to_string()));
    }

    #[test]
    #[serial]
    fn test_append_only() {
        let mut g = read_config();
        fs::remove_dir_all(&g.fs_path).ok();
        g.open_or_clone().unwrap();
        
        // add new file
        let added = util::create_random_file("/tmp");
        let name = added.file_name().unwrap().to_str().unwrap();
        g.post(vec![(name, &added)], "new file").unwrap();
        
        // create 2nd repo after creating file but before making modification
        let mut g2 = read_config();
        g2.fs_path.push_str("_");
        fs::remove_dir_all(&g2.fs_path).ok();
        g2.open_or_clone().unwrap();

        fs::remove_dir_all(&g.fs_path).ok();
        g.open_or_clone().unwrap();
        let files = g.list();
        assert!(files.contains(&name.to_string()));
        
        let modify = added.to_str().unwrap();
        println!("Modifying {}", modify);
        util::modify_file(&modify);
        let mut result = g.post(vec![(name, &added)], "file modification");
        // cannot modify upstream in append_only mode
        assert!(result.is_err());
        
        g.append_only = false;
        result = g.post(vec![(name, &added)], "file modification");
        assert!(result.is_ok());

        g2.append_only = true;
        result = g2.refresh();
        // cannot modify downstream in append_only mode
        assert!(result.is_err());

        g2.append_only = false;
        result = g2.refresh();
        assert!(result.is_ok());
    }
}
