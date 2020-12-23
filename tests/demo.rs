use std::marker::PhantomData;
use std::collections::HashSet;
use std::iter::FromIterator;
use std::fs;
use std::path::Path;
use std::{thread, time};

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
use cursive::views::{Dialog, DummyView, LinearLayout, TextView, Panel, ScrollView};
use cursive::theme::{Color, PaletteColor, Theme};
use cursive::view::ScrollStrategy;
use cursive::Cursive;


use simplelog::*;
use log::{info, warn};

pub fn gen_config<E: Element, G: Group<E>>(group: &G, contests: u32, trustee_pks: Vec<SPublicKey>,
    ballotbox_pk: SPublicKey) -> rmx::artifact::Config<E, G> {

    let id = Uuid::new_v4();

    let cfg = rmx::artifact::Config {
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
struct DemoLogSink {
    pub cb_sink: cursive::CbSink
}
struct Demo<E, G> {
    pub cb_sink: cursive::CbSink,
    trustees: Vec<Protocol<E, G, MemoryBulletinBoard<E, G>>>,
    bb_keypair: Keypair,
    config: rmx::artifact::Config<E, G>,
    board: MemoryBulletinBoard<E, G>
}
impl<E: Element + DeserializeOwned, G: Group<E> + DeserializeOwned> Demo<E, G> {
    fn new(sink: cursive::CbSink, group: &G, trustees: u32, contests: u32) -> Demo<E, G> {
        let local1 = "/tmp/local";
        let local2 = "/tmp/local2";
        let local_path = Path::new(&local1);
        fs::remove_dir_all(local_path).ok();
        fs::create_dir(local_path).ok();
        let local_path = Path::new(&local2);
        fs::remove_dir_all(local_path).ok();
        fs::create_dir(local_path).ok();
        
        let mut trustee_pks = Vec::new();
        let mut prots = Vec::new();
        
        for i in 0..trustees {
            let local = format!("/tmp/local{}", i);
            let local_path = Path::new(&local);
            fs::remove_dir_all(local_path).ok();
            fs::create_dir(local_path).ok();
            let trustee: Trustee<E, G> = Trustee::new(local.to_string());
            trustee_pks.push(trustee.keypair.public);
            let prot: Protocol<E, G, MemoryBulletinBoard<E, G>> = Protocol::new(trustee);
            prots.push(prot);

        }
        let mut csprng = OsRng;
        let bb_keypair = Keypair::generate(&mut csprng);
        let mut bb = MemoryBulletinBoard::<E, G>::new();
        let cfg = gen_config(group, contests, trustee_pks, bb_keypair.public);
        let cfg_b = bincode::serialize(&cfg).unwrap();
        let tmp_file = util::write_tmp(cfg_b).unwrap();
        bb.add_config(&ConfigPath(tmp_file.path().to_path_buf()));

        Demo {
            cb_sink: sink,
            trustees: prots,
            bb_keypair: bb_keypair,
            config: cfg,
            board: bb
        }
    }
    fn add_ballots(&mut self) {
        for i in 0..self.config.contests {
            let pk_b = self.board.get_unsafe(MemoryBulletinBoard::<E, G>::public_key(i, 0));
            if pk_b.is_some() {
                let pk: PublicKey<E, G> = bincode::deserialize(pk_b.unwrap()).unwrap();
                
                let (plaintexts, ciphertexts) = util::random_encrypt_ballots(100, &pk);
                // all_plaintexts.push(plaintexts);
                let ballots = Ballots { ciphertexts };
                let ballots_b = bincode::serialize(&ballots).unwrap();
                let ballots_h = hashing::hash(&ballots);
                let cfg_h = hashing::hash(&self.config);
                let ss = SignedStatement::ballots(&cfg_h, &ballots_h, i, &self.bb_keypair);
                
                let ss_b = bincode::serialize(&ss).unwrap();
                
                let f1 = util::write_tmp(ballots_b).unwrap();
                let f2 = util::write_tmp(ss_b).unwrap();
                info!("Adding {} ballots", ballots.ciphertexts.len());
                self.board.add_ballots(&BallotsPath(f1.path().to_path_buf(), f2.path().to_path_buf()), i);
            }
            else {
                info!("Cannot add ballots for contest=[{}], no pk yet", i);
            }
        }
    }
    fn step(&mut self, t: usize) {
        let trustee = &self.trustees[t];
        trustee.step(&mut self.board);
    }
    fn set_message(&self, target: String, message: String) {
        self.cb_sink.send(Box::new(move |s: &mut cursive::Cursive| {
            s.call_on_name(&target, |view: &mut TextView| {
                view.set_content(message); 
            });
        }))
        .unwrap();
    }
    fn append_message(&self, target: String, message: String) {
        self.cb_sink.send(Box::new(move |s: &mut cursive::Cursive| {
            s.call_on_name(&target, |view: &mut TextView| {
                view.append(message); 
            });
        }))
        .unwrap();
    }
    fn writer(&self) -> DemoLogSink {
        DemoLogSink {
            cb_sink: self.cb_sink.clone()
        }
    }
}
use std::rc::Rc;
use std::cell::RefCell;

impl std::io::Write for DemoLogSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let message = Arc::new(
            buf.to_owned()
        );
        
        self.cb_sink.send(Box::new( 
            move |s: &mut cursive::Cursive| {
            let data = s.user_data::<u32>().unwrap_or(&mut 0).clone();
            s.call_on_name(&data.to_string(), |view: &mut ScrollView<TextView>| {
                let bytes = Arc::try_unwrap(message).unwrap();
                let string = std::str::from_utf8(&bytes).unwrap();
                view.get_inner_mut().append(string);
                view.scroll_to_bottom();
                // view.append(data.to_string());
            });
            
        }))
        .unwrap();

        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.cb_sink.send(Box::new(cursive::Cursive::noop));

        Ok(())
    }
}

type DemoArc<E, G> = Arc<Mutex<Demo<E, G>>>;

#[test]
fn demo_tui() {
    
    let mut n: u32 = 0;
    let mut siv = cursive::default();
    let group = RugGroup::default();
    let trustees: u32 = 3;
    let contests = 2;
    let demo = Demo::new(siv.cb_sink().clone(), &group, trustees, contests);
    CombinedLogger::init(
        vec![
            // TermLogger::new(LevelFilter::Warn, Config::default(), TerminalMode::Mixed),
            WriteLogger::new(LevelFilter::Info, simplelog::Config::default(), demo.writer()),
        ]
    ).unwrap();
    
    let demo_arc = Arc::new(Mutex::new(
        demo
    ));
    let demo_arc2 = Arc::clone(&demo_arc);
    
    // start(Arc::clone(&model));
    // This example uses a LinearLayout to stick multiple views next to each other.
    
    let theme = custom_theme_from_cursive(&siv);
    siv.set_theme(theme);
    let text = "Ready";

    let mut layout = LinearLayout::vertical();
    for i in 0..trustees {
        let title = format!("Trustee {}", i);
        
        layout = layout.child(Panel::new(
            TextView::new(text)
            .scrollable().scroll_strategy(ScrollStrategy::StickToBottom).with_name(&i.to_string()))
            .title(title)
            .title_position(HAlign::Left)
        );
    }
    layout = layout.child(Panel::new(
            TextView::new("[q - Quit] [n - Protocol step] [b - Add ballots]")
        )
        .title("Help")
        .title_position(HAlign::Left)
        .fixed_height(3)
    );

    siv.add_fullscreen_layer(layout);
    siv.add_global_callback('q', |s| s.quit());
    siv.add_global_callback('n', move |s| {
        let mutex = Arc::clone(&demo_arc);
        if mutex.try_lock().is_ok() {
            s.call_on_name(&n.to_string(), |view: &mut ScrollView<TextView>| {
                view.get_inner_mut().set_content("");
            });
            s.set_user_data(n);
            step_t(Arc::clone(&demo_arc), n);
            n = (n + 1) % trustees;
        }
    });
    siv.add_global_callback('b', move |s| {
        let mutex = Arc::clone(&demo_arc2);
        if mutex.try_lock().is_ok() {
            s.set_user_data(0);
            s.call_on_name(&"0".to_string(), |view: &mut TextView| {
                view.set_content("");
            });
            ballots_t(Arc::clone(&demo_arc2));
        }
    });
    
    siv.run();
}

fn step_t<E: 'static + Element + DeserializeOwned, G: 'static + Group<E> + DeserializeOwned>(demo_arc: DemoArc<E, G>, t: u32) {
    std::thread::spawn(move || {
        step(Arc::clone(&demo_arc), t)
    });
}

fn ballots_t<E: 'static + Element + DeserializeOwned, G: 'static + Group<E> + DeserializeOwned>(demo_arc: DemoArc<E, G>) {
    std::thread::spawn(move || {
        ballots(Arc::clone(&demo_arc))
    });
}

fn step<E: 'static + Element + DeserializeOwned, G: Group<E> + DeserializeOwned>(demo_arc: DemoArc<E, G>, t: u32) {
    let mut demo = demo_arc.lock().unwrap();
    demo.step(t as usize);
}

fn ballots<E: 'static + Element + DeserializeOwned, G: Group<E> + DeserializeOwned>(demo_arc: DemoArc<E, G>) {
    let mut demo = demo_arc.lock().unwrap();
    demo.add_ballots();
}


fn custom_theme_from_cursive(siv: &Cursive) -> Theme {
    // We'll return the current theme with a small modification.
    let mut theme = siv.current_theme().clone();

    theme.palette[PaletteColor::Background] = Color::TerminalDefault;
    theme.palette[PaletteColor::Primary] = Color::Rgb(200, 200, 200);
    theme.palette[PaletteColor::View] = Color::TerminalDefault;

    theme
}

#[test]
fn demo_rug() {
    CombinedLogger::init(
        vec![
            TermLogger::new(LevelFilter::Info, simplelog::Config::default(), TerminalMode::Mixed)
        ]
    ).unwrap();
    let group = RugGroup::default();
    demo(group);
}

#[test]
fn demo_ristretto() {
    CombinedLogger::init(
        vec![
            TermLogger::new(LevelFilter::Info, simplelog::Config::default(), TerminalMode::Mixed)
        ]
    ).unwrap();
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
    
    let prot1: Protocol<E, G, MemoryBulletinBoard<E, G>> = Protocol::new(trustee1);
    let prot2: Protocol<E, G, MemoryBulletinBoard<E, G>> = Protocol::new(trustee2);

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