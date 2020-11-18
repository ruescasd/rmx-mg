use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::fs;

use git2::build::{CheckoutBuilder, RepoBuilder};
use git2::*;
use walkdir::{DirEntry, WalkDir};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct GitBulletinBoard {
    pub ssh_key_path: String,
    pub url: String,
    pub fs_path: String
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
        let object = repo.find_object(commit.id(), None)?;
        repo.reset(&object, git2::ResetType::Hard, None)?;
        
        let analysis = repo.merge_analysis(&[&commit])?;
    
        if analysis.0.is_up_to_date() {
            println!("Up to date");
            Ok(())
        }
        else if analysis.0.is_fast_forward() {        
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

    pub fn post(&self, files: Vec<(&str, &Path)>) -> Result<(), git2::Error> {
        let repo = self.open_or_clone()?;
        self.reset(&repo)?;
        for (target, source) in files {
            self.add(&repo, target, source)?;
        }
        self.push(&repo);

        Ok(())
    }

    pub fn list(&self) -> Vec<String> {
        let walker = WalkDir::new(&self.fs_path).into_iter();
        let files: Vec<String> = walker
            .filter_entry(|e| !is_hidden(e))
            .map(|e| e.unwrap().path().to_str().unwrap().to_string())
            .collect();

        files
    }

    fn open_or_clone(&self) -> Result<Repository, Error> {    
        if Path::new(&self.fs_path).exists() {
            Repository::open(&self.fs_path)
        }
        else {  
            let mut co = CheckoutBuilder::new();
            let mut fo = FetchOptions::new();
            let cb = remote_callbacks(&self.ssh_key_path);
            fo.remote_callbacks(cb);    
            RepoBuilder::new()
                .fetch_options(fo)
                .with_checkout(co)
                .clone(&self.url, Path::new(&self.fs_path))
        }
    }

    fn add(&self, repo: &Repository, target: &str, source: &Path) -> Result<Oid, git2::Error> {
        
        let target_path = Path::new(target);
        let target_file = Path::new(&self.fs_path).join(target_path);
        if target_file.is_file() && target_file.exists() {
            fs::remove_file(&target_file);
        }
        fs::copy(source, &target_file).unwrap();
        // adding to repo index uses relative path: &target_path
        add_and_commit(&repo, &target_path, 
            target_file.to_str().unwrap_or("default commit message"))
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
        remote.connect(Direction::Push)?;
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

fn add_and_commit(repo: &Repository, path: &Path, message: &str) -> Result<Oid, git2::Error> {
    let mut index = repo.index()?;
    index.add_path(path)?;
    let oid = index.write_tree()?;
    let signature = Signature::now("rmx", "rmx@foo.bar")?;
    let parent_commit = find_last_commit(&repo)?;
    let tree = repo.find_tree(oid)?;
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

/*use serial_test::serial;

#[test]
#[serial]
fn test_clone_or_open() {
    
    let g = read_config();
    fs::remove_dir_all(&g.fs_path);
    let repo = g.clone_or_open().unwrap();
    
    let dir = Path::new(&g.fs_path);
    assert!(dir.exists() && dir.is_dir());
}

#[test]
#[serial]
fn test_pull() {
    let g = read_config();
    fs::remove_dir_all(&g.fs_path);
    let repo = g.clone_or_open().unwrap();
    g.pull(&repo, false);
}*/

