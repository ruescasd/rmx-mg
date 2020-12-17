use std::fs;
use std::path::Path;
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

pub fn gen_config(group: Option<RugGroup>, contests: u32, trustee_pks: Vec<SPublicKey>) -> Config {
    let mut csprng = OsRng;

    let id = Uuid::new_v4();    
    let ballotbox_pk = Keypair::generate(&mut csprng).public; 

    let cfg = Config {
        id: id.as_bytes().clone(),
        rug_group: group,
        contests: contests, 
        ballotbox: ballotbox_pk, 
        trustees: trustee_pks
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

    let cfg = gen_config(Some(group), 2, trustee_pks);
    trustee1.add_config(&cfg, &mut bb);
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

    prot1.step(&mut bb);
    prot2.step(&mut bb);

    
    
    
    
    /*
    let self_pk = trustee_pks[0];
    let other_pk = trustee_pks[1];
    let cfg = Config {
        id: id.as_bytes().clone(),
        rug_group: Some(group),
        contests: contests, 
        ballotbox: ballotbox_pk, 
        trustees: trustee_pks
    };
    
    let cfg_path = ls1.set_config(&cfg);
    bb.add_config(&cfg_path);
    
    let mut prot = Protocol::new(bb);
    let actions = prot.process_facts(self_pk).check_config;

    let cfg_h = hashing::hash(&cfg);
    let expected = Act::CheckConfig(cfg_h);
        
    assert!(actions[0] == expected);
    
    let ss = SignedStatement::config(&cfg, &trustee_kps[0]);
    let stmt_path = ls1.set_config_stmt(&expected, &ss);

    prot.board.add_config_stmt(&stmt_path, 0);
    
    let actions = prot.process_facts(self_pk).all_actions;
    assert!(actions.len() == 0);

    let ss = SignedStatement::config(&cfg, &trustee_kps[1]);
    let stmt_path = ls2.set_config_stmt(&expected, &ss);

    prot.board.add_config_stmt(&stmt_path, 1);
    let actions = prot.process_facts(self_pk).post_share;

    assert!(actions.len() as u32 == contests);

    let km1 = &trustee_keymakers[0];
    let km2 = &trustee_keymakers[1];
    
    let (pk1, proof1) = km1.share();
    let (pk2, proof2) = km2.share();
    let esk1 = km1.get_encrypted_sk();
    let esk2 = km2.get_encrypted_sk();
    
    let share1 = Keyshare {
        share: pk1,
        proof: proof1,
        encrypted_sk: esk1
    };
    let share2 = Keyshare {
        share: pk2,
        proof: proof2,
        encrypted_sk: esk2
    };

    let share1_h = hashing::hash(&share1);
    let share2_h = hashing::hash(&share2);
    let act = Act::PostShare(cfg_h, 0);
    let ss1 = SignedStatement::keyshare(&cfg, share1_h, 0, &trustee_kps[0]);
    let ss2 = SignedStatement::keyshare(&cfg, share2_h, 0, &trustee_kps[1]);
    let share1_path = ls1.set_share(&act, share1, &ss1);
    let share2_path = ls2.set_share(&act, share2, &ss2);

    prot.board.add_share(&share1_path, 0, 0);
    prot.board.add_share(&share2_path, 0, 1);

    let output = prot.process_facts(self_pk);

    // assert!(output.pk_shares_ok.len() == 1);
    assert!(output.combine_shares.len() == 1);
    assert!(output.post_share.len() == 1);

    let share1 = prot.board.get_share(0, 0).unwrap();
    let share2 = prot.board.get_share(0, 1).unwrap();
    let gr = &cfg.rug_group.clone().unwrap();
    assert!(Keymaker::verify_share(gr, &share1.share, &share1.proof));
    assert!(Keymaker::verify_share(gr, &share2.share, &share2.proof));
    
    let pk = Keymaker::combine_pks(gr, vec![share1.share, share2.share]);
    let pk_h = hashing::hash(&pk);
    let ss1 = SignedStatement::public_key(&cfg, pk_h, 0, &trustee_kps[0]);
    let act = output.combine_shares[0];
    let pk_path = ls1.set_pk(&act, pk, &ss1);
    prot.board.set_pk(&pk_path, 0);

    let output = prot.process_facts(self_pk);
    assert!(output.combine_shares.len() == 0);
    assert!(output.check_pk.len() == 0);

    let output = prot.process_facts(other_pk);
    assert!(output.check_pk.len() == 1);
    let act = output.check_pk[0];

    let ss2 = SignedStatement::public_key(&cfg, pk_h, 0, &trustee_kps[1]);
    let pk_stmt_path = ls2.set_pk_stmt(&act, &ss2);
    prot.board.set_pk_stmt(&pk_stmt_path, 0, 1);

    let output = prot.process_facts(self_pk);*/
}