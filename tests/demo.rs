use std::fs;
use std::path::Path;
use std::marker::PhantomData;

use serde::Serialize;
use serde::de::DeserializeOwned;
use ed25519_dalek::{Keypair, Signer};

use uuid::Uuid;
use rand_core::OsRng;
use tempfile::NamedTempFile;
use rug::Integer;

use rmx::hashing;
use rmx::artifact::*;
use rmx::keymaker::Keymaker;
use rmx::rug_b::*;
use rmx::bb::BulletinBoard;
use rmx::memory_bb::*;
use rmx::protocol::*;
use rmx::action::*;
use rmx::util;
use rmx::localstore::*;
use rmx::arithm::Element;
use rmx::group::Group;

use ed25519_dalek::PublicKey as SPublicKey;

pub fn gen_config(group: RugGroup, contests: u32, trustee_pks: Vec<SPublicKey>) -> Config<Integer, RugGroup> {
    let mut csprng = OsRng;

    let id = Uuid::new_v4();    
    let ballotbox_pk = Keypair::generate(&mut csprng).public; 

    let cfg = Config {
        id: id.as_bytes().clone(),
        group: group,
        contests: contests, 
        ballotbox: ballotbox_pk, 
        trustees: trustee_pks,
        phantom_e: PhantomData
    };

    cfg
}


#[test]
fn demo() {
    let local1 = "/tmp/local";
    let local2 = "/tmp/local2";
    let group = RugGroup::default();
    let trustee1 = Trustee::new(&group, local1.to_string());
    let trustee2 = Trustee::new(&group, local2.to_string());
    let mut bb = MemoryBulletinBoard::<Integer, RugGroup>::new();
    
    let mut trustee_pks = Vec::new();
    trustee_pks.push(trustee1.keypair.public);
    trustee_pks.push(trustee2.keypair.public);

    let cfg = gen_config(group, 2, trustee_pks);
    let cfg_b = bincode::serialize(&cfg).unwrap();
    let tmp_file = util::write_tmp(cfg_b).unwrap();
    bb.add_config(&ConfigPath(tmp_file.path().to_path_buf()));
    
    // trustee1.add_config(&cfg, &mut bb);
    let mut prot1: Protocol2 <
        Integer, 
        RugGroup, 
        MemoryBulletinBoard<Integer, RugGroup>
    > = Protocol2::new(trustee1);

    let mut prot2: Protocol2 <
        Integer, 
        RugGroup, 
        MemoryBulletinBoard<Integer, RugGroup>
    > = Protocol2::new(trustee2);

    // check config
    prot1.step(&mut bb);
    prot2.step(&mut bb);
    
    // post share
    prot1.step(&mut bb);
    prot2.step(&mut bb);

    // combines shares
    prot1.step(&mut bb);
    // check pk
    prot2.step(&mut bb);

    prot1.step(&mut bb);
    prot2.step(&mut bb);
}