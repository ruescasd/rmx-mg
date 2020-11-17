use git2::build::{CheckoutBuilder, RepoBuilder};
use git2::{FetchOptions, Progress, RemoteCallbacks, Cred, Repository,
    Commit, ObjectType, StatusOptions, Error, RebaseOptions, 
    RebaseOperation, Signature, Direction, Oid};
use std::cell::RefCell;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::fs;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct GitBulletinBoard {
    pub ssh_path: String,
    pub url: String,
    pub fs_path: String
}

impl GitBulletinBoard {
    
    fn clone_or_open(&self) -> Result<Repository, Error> {    
        if Path::new(&self.fs_path).exists() {
            Repository::open(&self.fs_path)
        }
        else {  
            let mut co = CheckoutBuilder::new();
            let mut fo = FetchOptions::new();
            let cb = remote_callbacks(&self.ssh_path);
            fo.remote_callbacks(cb);    
            RepoBuilder::new()
                .fetch_options(fo)
                .with_checkout(co)
                .clone(&self.url, Path::new(&self.fs_path))
        }
    }
    
    // resets the working copy to match that of the remote
    // local commits and working copy are discarded
    fn reset(&self, repo: &Repository) -> Result<(), git2::Error> {
        let mut remote = repo.find_remote("origin")?;
        let mut fo = FetchOptions::new();
        fo.remote_callbacks(remote_callbacks(&self.ssh_path));
        fo.download_tags(git2::AutotagOption::All);
        remote.fetch(&["master"], Some(&mut fo), None)?;
        let fetch_head = repo.find_reference("FETCH_HEAD")?;
        let commit = repo.reference_to_annotated_commit(&fetch_head)?;
        let object = repo.find_object(commit.id(), None)?;
        repo.reset(&object, git2::ResetType::Hard, None)
    }
    
    // pulls in remote changes
    // if rebase = true and local changes were committed ahead of the remote, a rebase is attempted
    // returns true if local copy is up to date
    // returns false if the local copy is ahead and a push is required after rebase
    fn pull(&self, repo: &Repository, rebase: bool) -> Result<bool, git2::Error> {
        let mut remote = repo.find_remote("origin").unwrap();
        let mut fo = FetchOptions::new();
        let cb = remote_callbacks(&self.ssh_path);
        fo.remote_callbacks(cb);
        fo.download_tags(git2::AutotagOption::All);
        remote.fetch(&["master"], Some(&mut fo), None)?;
    
        let fetch_head = repo.find_reference("FETCH_HEAD")?;
        let commit = repo.reference_to_annotated_commit(&fetch_head)?;
        let analysis = repo.merge_analysis(&[&commit])?;
    
        if analysis.0.is_up_to_date() {
            println!("Up to date");
            Ok(true)
        }
        else if analysis.0.is_fast_forward() {        
            let refname = format!("refs/heads/master");
            let mut r = repo.find_reference(&refname)?;
            fast_forward(&repo, &mut r, &commit)?;
            Ok(true)
        }
        else {
            println!("Merge required");
            if rebase {
                let head = repo.head()?;
                let branch = repo.reference_to_annotated_commit(&head)?;
                let upstream = repo.find_annotated_commit(commit.id())?;
    
                let mut opts: RebaseOptions<'_> = RebaseOptions::default();
                let mut rebase = repo
                    .rebase(Some(&branch), Some(&upstream), None, Some(&mut opts))?;
    
                let sig = Signature::now("rmx", "rmx@foo.bar").unwrap();
                let mut abort = false;
                for i in 0..rebase.len() {
                    print!("Applying patch {}..", i + 1);
                    let op: RebaseOperation = rebase.next().unwrap()?;
                    match rebase.commit(None, &sig, None) {
                        Ok(_) => println!("ok"),
                        Err(_) => {
                            println!("failed, aborting rebase");
                            abort = true;
                            break;
                        }
                    }
                }
                
                if abort {
                    rebase.abort();
                    Err(git2::Error::from_str("rebase failed"))
                }
                else {
                    rebase.finish(None)?;
                    Ok(false)
                }
            }
            else {
                Ok(false)
            }
        }
    }
}

fn find_last_commit(repo: &Repository) -> Result<Commit, Error> {
    let obj = repo.head()?.resolve()?.peel(ObjectType::Commit)?;
    match obj.into_commit() {
        Ok(c) => Ok(c),
        _ => Err(git2::Error::from_str("Couldn't find commit"))
    }
} 

// 1. reset working copy
// 2. copy file to send
// 3. attempt to push
// 3a. if push ok done
// 3b. if push fail attempt rebase
// 3a1. if rebase ok, go to 3
// 3a2. if rebase fail, go to 1
fn send(target: &str, source: &Path) {
    let target_file = Path::new(target);
    if target_file.is_file() && target_file.exists() {
        fs::remove_file(target_file);
    }
    fs::copy(source, target_file).unwrap();
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
    // let file_path = Path::new(repo_root.as_str()).join(relative_path);
}

fn push(repo: &Repository) -> Result<(), git2::Error> {
    let mut remote = repo.find_remote("origin").unwrap();
    remote.connect(Direction::Push)?;
    remote.push(&["refs/heads/master:refs/heads/master"], None)
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

// const ssh_path: &str = "/mnt/c/Users/ruesc/.ssh/id_rsa";
// const test_url: &str = "git@github.com:ruescasd/bb.git";
// const test_path: &str = "/tmp/repo2";


fn read_config() -> GitBulletinBoard {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("resources/test/git_bb.json");
    let cfg = fs::read_to_string(d).unwrap();
    let g: GitBulletinBoard = serde_json::from_str(&cfg).unwrap();

    g
}

use serial_test::serial;

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
}

