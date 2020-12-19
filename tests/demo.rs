

use std::marker::PhantomData;

use rand_core::OsRng;

use ed25519_dalek::{Keypair};

use uuid::Uuid;

use rug::Integer;

use rmx::statement::SignedStatement;
use rmx::artifact::*;
use rmx::hashing;

use rmx::rug_b::*;
use rmx::bb::BulletinBoard;
use rmx::memory_bb::*;
use rmx::protocol::*;

use rmx::util;
use rmx::localstore::*;

use ed25519_dalek::PublicKey as SPublicKey;

pub fn gen_config(group: &RugGroup, contests: u32, trustee_pks: Vec<SPublicKey>,
    ballotbox_pk: SPublicKey) -> Config<Integer, RugGroup> {

    let id = Uuid::new_v4();

    let cfg = Config {
        id: id.as_bytes().clone(),
        group: group.clone(),
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
    let mut csprng = OsRng;
    let bb_keypair = Keypair::generate(&mut csprng);
    
    let mut bb = MemoryBulletinBoard::<Integer, RugGroup>::new();
    
    let mut trustee_pks = Vec::new();
    trustee_pks.push(trustee1.keypair.public);
    trustee_pks.push(trustee2.keypair.public);
    
    let contests = 2;
    let cfg = gen_config(&group, contests, trustee_pks, bb_keypair.public);
    let cfg_b = bincode::serialize(&cfg).unwrap();
    let tmp_file = util::write_tmp(cfg_b).unwrap();
    bb.add_config(&ConfigPath(tmp_file.path().to_path_buf()));
    
    let prot1: Protocol2 <
        Integer, 
        RugGroup, 
        MemoryBulletinBoard<Integer, RugGroup>
    > = Protocol2::new(trustee1);

    let prot2: Protocol2 <
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

    let actions = prot1.step(&mut bb);
    assert!(actions == 0);
    let actions = prot2.step(&mut bb);
    prot2.step(&mut bb);
    assert!(actions == 0);
       
    for i in 0..contests {
        let ballots = util::random_rug_ballots(100, &group);
        let ballots_b = bincode::serialize(&ballots).unwrap();
        let ballots_h = hashing::hash(&ballots);
        let cfg_h = hashing::hash(&cfg);
        let ss = SignedStatement::ballots(&cfg_h, &ballots_h, i, &bb_keypair);
        
        let ss_b = bincode::serialize(&ss).unwrap();
        
        let f1 = util::write_tmp(ballots_b).unwrap();
        let f2 = util::write_tmp(ss_b).unwrap();
        println!("Adding {} ballots", ballots.ciphertexts.len());
        bb.add_ballots(&BallotsPath(f1.path().to_path_buf(), f2.path().to_path_buf()), i);
    }
    
    prot1.step(&mut bb);
    prot2.step(&mut bb);
}