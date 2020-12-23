use std::marker::PhantomData;
use std::collections::HashSet;
use std::iter::FromIterator;
use std::fs;
use std::path::Path;


use rand::rngs::OsRng;
use ed25519_dalek::{Keypair, PublicKey as SPublicKey};
use curve25519_dalek::ristretto::RistrettoPoint;
use uuid::Uuid;
use serde::de::DeserializeOwned;
use rug::Integer;

use rmx::statement::SignedStatement;
use rmx::artifact::*;
use rmx::elgamal::PublicKey;
use rmx::hashing;
use rmx::group::Group;
use rmx::arithm::Element;
use rmx::rug_b::*;
use rmx::ristretto_b::*;
use rmx::bb::BulletinBoard;
use rmx::bb::Names;
use rmx::memory_bb::*;
use rmx::protocol::*;
use rmx::util;
use rmx::localstore::*;

use cursive::align::HAlign;
use cursive::traits::*;
use cursive::views::{Dialog, DummyView, LinearLayout, TextView, Panel};
use cursive::theme::{Color, PaletteColor, Theme};
use cursive::Cursive;

pub fn gen_config<E: Element, G: Group<E>>(group: &G, contests: u32, trustee_pks: Vec<SPublicKey>,
    ballotbox_pk: SPublicKey) -> Config<E, G> {

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

use std::sync::{Arc, Mutex};
struct ModelData {
    pub cb_sink: cursive::CbSink
}
type Model = Arc<Mutex<ModelData>>;

#[test]
fn demo_tui() {
    let mut siv = cursive::default();

    let model = Arc::new(Mutex::new(ModelData {
        cb_sink: siv.cb_sink().clone()
    }));
    
    start(Arc::clone(&model));
    // This example uses a LinearLayout to stick multiple views next to each other.
    
    let theme = custom_theme_from_cursive(&siv);
    siv.set_theme(theme);

    // Some description text. We want it to be long, but not _too_ long.
    let text = "This is a very simple example of linear layout. Two views \
                are present, a short title above, and this text. The text \
                has a fixed width, and the title is centered horizontally.";

    // We'll create a dialog with a TextView serving as a title
    siv.add_fullscreen_layer(
        LinearLayout::vertical()
            // Disabling scrollable means the view cannot shrink.
            .child(Panel::new(
                    TextView::new(text).with_name("0")
                )
                .title("test")
                .title_position(HAlign::Left)
            )
            // The other views will share the remaining space.
            .child(TextView::new(text).with_name("1").scrollable())
            .child(TextView::new(text).with_name("2").scrollable())
            .child(TextView::new(text).with_name("3").scrollable())
    );

    siv.add_global_callback('q', |s| s.quit());
    
    siv.run();
}

fn start(model: Model) {
    std::thread::spawn(move || {
        go(Arc::clone(&model))
    });
}
use std::{thread, time};

fn go(model: Model) {
    let mut x = 0;
    loop {
        x = x + 1;
        message(&model, "0".to_string(), x.to_string());
        
        let sec = time::Duration::from_millis(1000);

        thread::sleep(sec);
    }
}

fn message(model: &Model, target: String, message: String) {
    let model = model.lock().unwrap();
    model.cb_sink
        .send(Box::new(move |s: &mut cursive::Cursive| {
            s.call_on_name(&target, |view: &mut TextView| {
                view.set_content(message); 
            });
        }))
        .unwrap();
}

fn custom_theme_from_cursive(siv: &Cursive) -> Theme {
    // We'll return the current theme with a small modification.
    let mut theme = siv.current_theme().clone();

    theme.palette[PaletteColor::Background] = Color::TerminalDefault;

    theme
}

#[test]
fn demo_rug() {
    let group = RugGroup::default();
    demo(group);
}

#[test]
fn demo_ristretto() {
    let group = RistrettoGroup;
    demo(group);
}

fn demo<E: Element + DeserializeOwned, G: Group<E> + DeserializeOwned>(group: G) {
    
    let local1 = "/tmp/local";
    let local2 = "/tmp/local2";
    let local_path = Path::new(&local1);
    fs::remove_dir_all(local_path).ok();
    fs::create_dir(local_path).ok();
    let local_path = Path::new(&local2);
    fs::remove_dir_all(local_path).ok();
    fs::create_dir(local_path).ok();

    let trustee1: Trustee<E, G> = Trustee::new(local1.to_string());
    let trustee2: Trustee<E, G> = Trustee::new(local2.to_string());
    let mut csprng = OsRng;
    let bb_keypair = Keypair::generate(&mut csprng);
    let mut bb = MemoryBulletinBoard::<E, G>::new();
    
    let mut trustee_pks = Vec::new();
    trustee_pks.push(trustee1.keypair.public);
    trustee_pks.push(trustee2.keypair.public);
    
    let contests = 3;
    let cfg = gen_config(&group, contests, trustee_pks, bb_keypair.public);
    let cfg_b = bincode::serialize(&cfg).unwrap();
    let tmp_file = util::write_tmp(cfg_b).unwrap();
    bb.add_config(&ConfigPath(tmp_file.path().to_path_buf()));
    
    let prot1: Protocol2<E, G, MemoryBulletinBoard<E, G>> = Protocol2::new(trustee1);
    let prot2: Protocol2<E, G, MemoryBulletinBoard<E, G>> = Protocol2::new(trustee2);

    // mix position 0
    prot1.step(&mut bb);
    // verify mix position 0
    prot2.step(&mut bb);

    // nothing
    prot1.step(&mut bb);
    // mix position 1
    prot2.step(&mut bb);

    // check mix position 1
    prot1.step(&mut bb);
    // partial decryptions
    prot2.step(&mut bb);

    // partial decryptions
    prot1.step(&mut bb);
    // nothing
    prot2.step(&mut bb);

    // combine decryptions
    prot1.step(&mut bb);
    
    let mut all_plaintexts = Vec::with_capacity(contests as usize);
    
    println!("=================== ballots ===================");
    for i in 0..contests {
        let pk_b = bb.get_unsafe(MemoryBulletinBoard::<E, G>::public_key(i, 0)).unwrap();
        let pk: PublicKey<E, G> = bincode::deserialize(pk_b).unwrap();
        
        let (plaintexts, ciphertexts) = util::random_encrypt_ballots(100, &pk);
        all_plaintexts.push(plaintexts);
        let ballots = Ballots { ciphertexts };
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
    println!("===============================================");

    // mix position 0
    prot1.step(&mut bb);
    // verify mix position 0
    prot2.step(&mut bb);

    // nothing
    prot1.step(&mut bb);
    // mix position 1
    prot2.step(&mut bb);

    // check mix position 1
    prot1.step(&mut bb);
    // partial decryptions
    prot2.step(&mut bb);

    // partial decryptions
    prot1.step(&mut bb);
    // nothing
    prot2.step(&mut bb);

    // combine decryptions
    prot1.step(&mut bb);

    for i in 0..contests {
        let decrypted_b = bb.get_unsafe(MemoryBulletinBoard::<E, G>::plaintexts(i, 0)).unwrap();
        let decrypted: Plaintexts<E> = bincode::deserialize(decrypted_b).unwrap();
        let decoded: Vec<E::Plaintext> = decrypted.plaintexts.iter().map(|p| {
            group.decode(&p)
        }).collect();
        let p1: HashSet<&E::Plaintext> = HashSet::from_iter(all_plaintexts[i as usize].iter().clone());
        let p2: HashSet<&E::Plaintext> = HashSet::from_iter(decoded.iter().clone());
        
        print!("Comparing plaintexts contest=[{}]...", i);
        assert!(p1 == p2);
        println!("Ok");
    }
}