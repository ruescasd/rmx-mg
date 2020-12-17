use std::collections::HashSet;
use std::marker::PhantomData;

use serde::{Deserialize, Serialize};
use ed25519_dalek::PublicKey as SPublicKey;
use ed25519_dalek::{Verifier, Signature};

use crepe::crepe;

use crate::hashing::*;
use crate::hashing;
use crate::artifact::*;
use crate::bb::*;
use crate::util;
use crate::arithm::Element;
use crate::group::Group;
use crate::action::Act;
use crate::util::short;
use std::fmt::Debug;

pub type TrusteeTotal = u32;
pub type TrusteeIndex = u32;
pub type ContestIndex = u32;
pub type ConfigHash = Hash;
pub type ShareHash = Hash;
pub type PkHash = Hash;
pub type BallotsHash = Hash;
pub type MixHash = Hash;
pub type DecryptionHash = Hash;
pub type PlaintextsHash = Hash;
pub type Hashes = [Hash; 10];
type OutputF = (HashSet<Do>, HashSet<ConfigOk>, HashSet<PkSharesOk>, HashSet<PkOk>, 
    HashSet<PkSharesUpTo>, HashSet<ConfigSignedUpTo>, HashSet<Contest>,
    HashSet<PkSignedUpTo>);


pub struct Protocol<E: Element, G: Group<E>, B: BulletinBoard<E, G>> {
    pub board: B,
    phantom_e: PhantomData<E>,
    phantom_g: PhantomData<G>
}

impl<E: Element, G: Group<E>, B: BulletinBoard<E, G>> Protocol<E, G, B> {

    pub fn new(board: B) -> Protocol<E, G, B> {
        Protocol {
            board: board,
            phantom_e: PhantomData,
            phantom_g: PhantomData
        }
    }
    
    fn get_facts(&self, self_pk: SPublicKey) -> Vec<InputFact> {
    
        let svs = self.board.get_statements();
        println!("SVerifiers: {}", svs.len());
        let mut facts: Vec<InputFact> = svs.iter()
            .map(|sv| sv.verify(&self.board))
            .filter(|f| f.is_some())
            .map(|f| f.unwrap())
            .collect();
        
        if let Some(cfg) = self.board.get_config_unsafe() {
            let trustees = cfg.trustees.len();
            
            let self_pos = cfg.trustees.iter()
                .position(|s| s.to_bytes() == self_pk.to_bytes())
                .unwrap();
            let hash = hashing::hash(&cfg);
            let contests = cfg.contests;

            let f = InputFact::config_present(
                hash,
                contests,
                trustees as u32,
                self_pos as u32
            );
            facts.push(f);
        };

        facts
    }
    
    pub fn process_facts(&self, self_pk: SPublicKey) -> Facts {
        let mut runtime = Crepe::new();
        let input_facts = self.get_facts(self_pk);
        load_facts(&input_facts, &mut runtime);
        
        let output = runtime.run();
        let ret = Facts::new(input_facts, output);
        
        ret.print();

        ret
    }
}

pub struct Facts {
    pub(self) input_facts: Vec<InputFact>,
    pub all_actions: Vec<Act>,
    pub check_config: Vec<Act>,
    pub post_share: Vec<Act>,
    pub combine_shares: Vec<Act>,
    pub check_pk: Vec<Act>,
    pub check_mix: Vec<Act>,
    pub mix: Vec<Act>,
    pub partial_decrypt: Vec<Act>,
    pub combine_decryptions: Vec<Act>,
    pub check_plaintexts: Vec<Act>,
    config_ok: HashSet<ConfigOk>,
    pk_shares_ok: HashSet<PkSharesOk>,
    pk_ok: HashSet<PkOk>
}

impl Facts {
    fn new(input_facts: Vec<InputFact>, f: OutputF) -> Facts {
        let mut all_actions = vec![];
        let mut check_config = vec![];
        let mut post_share = vec![];
        let mut combine_shares = vec![];
        let mut check_pk = vec![];
        let mut check_mix = vec![];
        let mut mix = vec![];
        let mut partial_decrypt = vec![];
        let mut combine_decryptions = vec![];
        let mut check_plaintexts = vec![];
        
        let actions = f.0;
        for a in actions {
            match a.0 {
                Act::AddConfig => (),
                Act::CheckConfig(..) => check_config.push(a.0),
                Act::PostShare(..) => post_share.push(a.0),
                Act::CombineShares(..) => combine_shares.push(a.0),
                Act::CheckPk(..) => check_pk.push(a.0),
                Act::CheckMix(..) => check_mix.push(a.0),
                Act::Mix(..) => mix.push(a.0),
                Act::PartialDecrypt(..) => partial_decrypt.push(a.0),
                Act::CombineDecryptions(..) => combine_decryptions.push(a.0),
                Act::CheckPlaintexts(..) => check_plaintexts.push(a.0)
            }  
            all_actions.push(a.0);
        }

        let config_ok = f.1;
        let pk_shares_ok = f.2;
        let pk_ok = f.3;

        Facts{
            input_facts,
            all_actions,
            check_config,
            post_share,
            combine_shares,
            check_pk,
            check_mix,
            mix,
            partial_decrypt,
            combine_decryptions,
            check_plaintexts,
            config_ok,
            pk_shares_ok,
            pk_ok
        }
    }

    fn print(&self) {
        println!("======== Output facts [");
        let next = &self.config_ok;
        for f in next {
            println!("* ConfigOk {:?}", short(&f.0));
        }
        let next = &self.pk_shares_ok;
        for f in next {
            println!("* PkSharesOk {:?}", short(&f.0));
        }
        let next = &self.pk_ok;
        for f in next {
            println!("* PkOk {:?}", short(&f.0));
        }
        let next = &self.all_actions; 
        for f in next {
            println!("* Action {:?}", f);
        }
            
        println!("] \n");
    }

    pub fn pk_shares_len(&self) -> usize {
        self.pk_shares_ok.len()
    }
    pub fn pk_ok_len(&self) -> usize {
        self.pk_ok.len()
    }
    pub fn config_ok(&self) -> bool {
        self.config_ok.len() == 1
    }

    
}

fn load_facts(facts: &Vec<InputFact>, runtime: &mut Crepe) {
    println!("======== Input facts [");
    facts.into_iter().map(|f| {
        println!("* Input fact {:?}", f);
        match f {
            InputFact::ConfigPresent(x) => runtime.extend(&[*x]),
            InputFact::ConfigSignedBy(x) => runtime.extend(&[*x]),
            InputFact::PkShareSignedBy(x) => runtime.extend(&[*x]),
            InputFact::PkSignedBy(x) => runtime.extend(&[*x]),
            InputFact::BallotsSigned(x) => runtime.extend(&[*x]),
            InputFact::MixSignedBy(x) => runtime.extend(&[*x]),
            InputFact::DecryptionSignedBy(x) => runtime.extend(&[*x]),
            InputFact::PlaintextsSignedBy(x) => runtime.extend(&[*x])
        }
    }).count();
    println!("] \n");
}

#[derive(Debug)]
pub struct SVerifier {
    pub statement: SignedStatement,
    pub trustee: u32,
    pub contest: u32
}

impl SVerifier {
    fn verify<E: Element, G: Group<E>, B: BulletinBoard<E, G>>(&self, board: &B) -> Option<InputFact> {
        let statement = &self.statement.statement;
        let config = board.get_config_unsafe()?;
        let pk = config.trustees[self.trustee as usize];
        let statement_hash = hashing::hash(statement);
        let verified = pk.verify(&statement_hash, &self.statement.signature);
        let config_h = util::to_u8_64(&statement.hashes[0]);
        println!("* Verify returns: [{}] on [{:?}] from trustee [{}] for contest [{}]", verified.is_ok(), 
            &self.statement.statement.stype, &self.trustee, &self.contest
        );

        match statement.stype {
            StatementType::Config => {
                self.ret(
                    InputFact::config_signed_by(config_h, self.trustee),
                    verified.is_ok()
                )
            },
            StatementType::Keyshare => {
                let share_h = util::to_u8_64(&statement.hashes[1]);
                self.ret(
                    InputFact::share_signed_by(config_h, self.contest, share_h, self.trustee),
                    verified.is_ok()
                )
            },
            StatementType::PublicKey => {
                let pk_h = util::to_u8_64(&statement.hashes[1]);
                self.ret(
                    InputFact::pk_signed_by(config_h, self.contest, pk_h, self.trustee),
                    verified.is_ok()
                )
            },
            StatementType::Ballots => {
                let ballots_h = util::to_u8_64(&statement.hashes[1]);
                self.ret(
                    InputFact::ballots_signed(config_h, self.contest, ballots_h),
                    verified.is_ok()
                )
            },
            StatementType::Mix => {
                let mix_h = util::to_u8_64(&statement.hashes[1]);
                let ballots_h = util::to_u8_64(&statement.hashes[2]);
                self.ret(
                    InputFact::mix_signed_by(config_h, self.contest, mix_h, ballots_h, self.trustee),
                    verified.is_ok()
                )

            },
            StatementType::PDecryption => {
                let pdecryptions_h = util::to_u8_64(&statement.hashes[1]);
                let ballots_h = util::to_u8_64(&statement.hashes[2]);
                self.ret(
                    InputFact::decryption_signed_by(config_h, self.contest, pdecryptions_h, ballots_h, self.trustee),
                    verified.is_ok()
                )

            },
            StatementType::Plaintexts => {
                let plaintexts_h = util::to_u8_64(&statement.hashes[1]);
                let pdecryptions_h = util::to_u8_64(&statement.hashes[2]);
                self.ret(
                    InputFact::plaintexts_signed_by(config_h, self.contest, plaintexts_h, pdecryptions_h, self.trustee),
                    verified.is_ok()
                )
            }
        }
    }

    fn ret(&self, fact: InputFact, verified: bool) -> Option<InputFact> {
        if verified {
            Some(fact)
        } else {
            None
        }
    }
}

enum InputFact {
    ConfigPresent(ConfigPresent),
    ConfigSignedBy(ConfigSignedBy),
    PkShareSignedBy(PkShareSignedBy),
    PkSignedBy(PkSignedBy),
    BallotsSigned(BallotsSigned),
    MixSignedBy(MixSignedBy),
    DecryptionSignedBy(DecryptionSignedBy),
    PlaintextsSignedBy(PlaintextsSignedBy)
}
impl InputFact {
    fn config_present(c: ConfigHash, cn: ContestIndex, trustees: TrusteeIndex, 
        self_index: TrusteeIndex) -> InputFact {
        
        InputFact::ConfigPresent(ConfigPresent(c, cn, trustees, self_index))
    }
    fn config_signed_by(c: ConfigHash, trustee: TrusteeIndex) -> InputFact {
        InputFact::ConfigSignedBy(ConfigSignedBy(c, trustee))
    }
    fn share_signed_by(c: ConfigHash, contest: ContestIndex, share: ShareHash,
        trustee: TrusteeIndex) -> InputFact {
        
        InputFact::PkShareSignedBy(PkShareSignedBy(c, contest, share, trustee))
    }
    fn pk_signed_by(c: ConfigHash, contest: ContestIndex, pk: PkHash, 
        trustee: TrusteeIndex) -> InputFact {
        
        InputFact::PkSignedBy(PkSignedBy(c, contest, pk, trustee))
    }
    fn ballots_signed(c: ConfigHash, contest: ContestIndex, 
        ballots: BallotsHash) -> InputFact {
        
        InputFact::BallotsSigned(BallotsSigned(c, contest, ballots))
    }
    fn mix_signed_by(c: ConfigHash, contest: ContestIndex, mix: MixHash, 
        ballots: BallotsHash, trustee: TrusteeIndex) -> InputFact {
        
        InputFact::MixSignedBy(MixSignedBy(c, contest, mix, ballots, trustee))
    }
    fn decryption_signed_by(c: ConfigHash, contest: ContestIndex, decryption: DecryptionHash, 
        ballots: BallotsHash, trustee: TrusteeIndex) -> InputFact {
        
        InputFact::DecryptionSignedBy(DecryptionSignedBy(c, contest, decryption, ballots, trustee))
    }
    fn plaintexts_signed_by(c: ConfigHash, contest: ContestIndex, plaintexts: PlaintextsHash,
        decryptions: DecryptionHash, trustee: TrusteeIndex) -> InputFact {
        
        InputFact::PlaintextsSignedBy(
            PlaintextsSignedBy(c, contest, plaintexts, decryptions, trustee)
        )
    }
}

#[derive(Copy, Clone, Hash, Eq, PartialEq)]
struct Sha512(Hash);

crepe! {
    @input
    struct ConfigPresent(ConfigHash, ContestIndex, TrusteeIndex, TrusteeIndex);
    @input
    struct ConfigSignedBy(ConfigHash, u32);
    @input
    struct PkShareSignedBy(ConfigHash, ContestIndex, ShareHash, TrusteeIndex);
    @input
    struct PkSignedBy(ConfigHash, ContestIndex, PkHash, TrusteeIndex);
    @input
    struct BallotsSigned(ConfigHash, ContestIndex, BallotsHash);
    @input
    struct MixSignedBy(ConfigHash, ContestIndex, MixHash, BallotsHash, TrusteeIndex);
    @input
    struct DecryptionSignedBy(ConfigHash, ContestIndex, DecryptionHash, BallotsHash, TrusteeIndex);
    @input
    struct PlaintextsSignedBy(ConfigHash, ContestIndex, PlaintextsHash, DecryptionHash, 
        TrusteeIndex);

    @input
    struct Test(Sha512);

    // 0
    @output
    struct Do(Act);
    // 1
    @output
    struct ConfigOk(ConfigHash);
    // 2
    @output
    struct PkSharesOk(ConfigHash, ContestIndex, Hashes);
    // 3
    @output
    struct PkOk(ConfigHash, ContestIndex, PkHash);
    // 4
    @output
    struct PkSharesUpTo(ConfigHash, ContestIndex, TrusteeIndex, Hashes);
    // 5
    @output
    struct ConfigSignedUpTo(ConfigHash, TrusteeIndex);
    // 6
    @output
    struct Contest(ConfigHash, ContestIndex);
    // 7
    @output
    struct PkSignedUpTo(ConfigHash, ContestIndex, PkHash, TrusteeIndex);
    
    Do(Act::CheckConfig(config)) <- 
        ConfigPresent(config, _, _, self_t),
        !ConfigSignedBy(config, self_t);
    
    Do(Act::PostShare(config, contest)) <- 
        ConfigPresent(config, _, _, self_t),
        Contest(config, contest),
        ConfigOk(config),
        !PkShareSignedBy(config, contest, _, self_t);
    
    Do(Act::CombineShares(config, contest, hashes)) <- 
        PkSharesOk(config, contest, hashes),
        ConfigPresent(config, _, _, 0),
        ConfigOk(config),
        !PkSignedBy(config, contest, _, 0);

    Do(Act::CheckPk(config, contest, pk_hash, hashes)) <- 
        ConfigPresent(config, _, _, self_t),
        ConfigOk(config),
        PkSharesOk(config, contest, hashes),
        PkSignedBy(config, contest, pk_hash, 0),
        !PkSignedBy(config, contest, pk_hash, self_t);
    
    ConfigSignedUpTo(config, 0) <-
        ConfigSignedBy(config, 0);
    
    ConfigSignedUpTo(config, trustee + 1) <- 
        ConfigSignedUpTo(config, trustee),
        ConfigSignedBy(config, trustee + 1);
    
    ConfigOk(config) <- 
        ConfigPresent(config, _, total_t, _),
        ConfigSignedUpTo(config, total_t - 1);
    
    PkSharesUpTo(config, contest, 0, first) <-
        PkShareSignedBy(config, contest, share, 0),
        let first = array_make(share);

    PkSharesUpTo(config, contest, trustee + 1, shares) <- 
        PkSharesUpTo(config, contest, trustee, input_shares),
        PkShareSignedBy(config, contest, share, trustee + 1),
        let shares = array_set(input_shares, trustee + 1, share);

    PkSharesOk(config, contest, shares) <-
        ConfigPresent(config, _, total_t, _),
        PkSharesUpTo(config, contest, total_t - 1, shares),
        ConfigOk(config);

    PkOk(config, contest, pk_hash) <-
        ConfigPresent(config, _, total_t, _),
        PkSignedUpTo(config, contest, pk_hash, total_t - 1),
        ConfigOk(config);
    
    PkSignedUpTo(config, contest, pk_hash, 0) <-
        PkSignedBy(config, contest, pk_hash, 0);

    PkSignedUpTo(config, contest, pk_hash, trustee + 1) <-
        PkSignedUpTo(config, contest, pk_hash, trustee),
        PkSignedBy(config, contest, pk_hash, trustee + 1);

    Contest(config, contests - 1) <-
        ConfigPresent(config, contests, _, _self);

    Contest(config, n - 1) <- Contest(config, n),
        (n > 0);
}

fn array_make(value: Hash) -> Hashes {
    let mut ret = [[0u8; 64]; 10];
    ret[0] = value;

    ret
}

fn array_set(mut input: Hashes, index: u32, value: Hash) -> Hashes {
    input[index as usize] = value;

    input
}

use std::fmt;
impl fmt::Debug for InputFact {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            InputFact::ConfigPresent(x) => write!(f, 
                "ConfigPresent: [contests={} trustees={} self={}] {:?}", x.1, x.2, x.3, short(&x.0)),
            InputFact::ConfigSignedBy(x) => write!(f, 
                "ConfigSignedBy: [{}] for config: {:?}", x.1, short(&x.0)),
            InputFact::PkShareSignedBy(x) => write!(f, 
                "PkShareSignedBy [contest={} trustee={}] for share: {:?}, for config: {:?}", 
                x.1, x.3, short(&x.2), short(&x.0)),
            InputFact::PkSignedBy(x) => write!(f, 
                "PkSignedBy [contest={} trustee={}] for pk: {:?}, for config: {:?}", 
                x.1, x.3, short(&x.2), short(&x.0)),
            
            InputFact::BallotsSigned(x) => write!(f, "BallotsSigned {:?}", short(&x.0)),
            InputFact::MixSignedBy(x) => write!(f, "MixSignedBy {:?}", short(&x.0)),
            InputFact::DecryptionSignedBy(x) => write!(f, "DecryptionSignedBy {:?}", short(&x.0)),
            InputFact::PlaintextsSignedBy(x) => write!(f, "PlaintextsSignedBy{:?}", short(&x.0))
        }
    }
}

#[cfg(test)]
mod tests {
    
    use std::fs;
    use std::path::Path;
    use ed25519_dalek::{Keypair, Signer};
    
    use uuid::Uuid;
    use rand_core::OsRng;
    use tempfile::NamedTempFile;
    use rug::Integer;

    use crate::hashing;
    use crate::artifact;
    use crate::keymaker::Keymaker;
    use crate::rug_b::*;
    use crate::memory_bb::*;
    use crate::protocol::*;
    use crate::action::*;
    use crate::util;
    use crate::localstore::*;
    
    #[test]
    fn test_crepe_config() {
        let mut csprng = OsRng;
        let mut bb = MemoryBulletinBoard::<Integer, RugGroup>::new();
        let local1 = "/tmp/local";
        let local_path1 = Path::new(local1);
        fs::remove_dir_all(local_path1).ok();
        fs::create_dir(local_path1).ok();
        let ls1: LocalStore<Integer, RugGroup> = LocalStore::new(local1.to_string());

        let local2 = "/tmp/local2";
        let local_path2 = Path::new(local2);
        fs::remove_dir_all(local_path2).ok();
        fs::create_dir(local_path2).ok();
        let ls2: LocalStore<Integer, RugGroup> = LocalStore::new(local2.to_string());

        let id = Uuid::new_v4();
        let group = RugGroup::default();
        let contests = 2;
        let ballotbox_pk = Keypair::generate(&mut csprng).public; 
        let trustees = 2;
        let mut trustee_kps = Vec::with_capacity(trustees);
        let mut trustee_pks = Vec::with_capacity(trustees);
        let mut trustee_keymakers: Vec<Keymaker<Integer, RugGroup>> = Vec::with_capacity(trustees);
        
        for _ in 0..trustees {
            let keypair = Keypair::generate(&mut csprng);
            let km = Keymaker::gen(&group);
            trustee_pks.push(keypair.public);
            trustee_kps.push(keypair);
            trustee_keymakers.push(km);
        }
        let self_pk = trustee_pks[0];
        let other_pk = trustee_pks[1];
        let cfg = artifact::Config {
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
        let ss1 = SignedStatement::keyshare(&cfg_h, &share1_h, 0, &trustee_kps[0]);
        let ss2 = SignedStatement::keyshare(&cfg_h, &share2_h, 0, &trustee_kps[1]);
        let share1_path = ls1.set_share(&act, share1, &ss1);
        let share2_path = ls2.set_share(&act, share2, &ss2);

        prot.board.add_share(&share1_path, 0, 0);
        prot.board.add_share(&share2_path, 0, 1);

        let output = prot.process_facts(self_pk);

        assert!(output.pk_shares_ok.len() == 1);
        assert!(output.combine_shares.len() == 1);
        assert!(output.post_share.len() == 1);

        let share1 = prot.board.get_share(0, 0, share1_h).unwrap();
        let share2 = prot.board.get_share(0, 1, share2_h).unwrap();
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

        let output = prot.process_facts(self_pk);
    }
}


use serde::de::DeserializeOwned;


use std::fs;
use std::path::Path;
use ed25519_dalek::{Keypair, Signer};

use uuid::Uuid;
use rand_core::OsRng;
use tempfile::NamedTempFile;
use rug::Integer;

use crate::artifact;
use crate::keymaker::Keymaker;
use crate::rug_b::*;
use crate::memory_bb::*;
use crate::action::*;
use crate::localstore::*;


pub struct Trustee<E: Element + Serialize + DeserializeOwned, 
    G: Group<E> + Serialize + DeserializeOwned> {

    pub keypair: Keypair,
    pub keymaker: Keymaker<E, G>,
    pub localstore: LocalStore<E, G>
}

impl<E: Element + Serialize + DeserializeOwned, 
    G: Group<E> + Serialize + DeserializeOwned> 
    Trustee<E, G> {
    
    pub fn new(group: &G, local_store: String) -> Trustee<E, G> {
        let mut csprng = OsRng;
        let local_path = Path::new(&local_store);
        fs::remove_dir_all(local_path).ok();
        fs::create_dir(local_path).ok();
        let localstore = LocalStore::new(local_store);
        let keypair = Keypair::generate(&mut csprng);
        let keymaker = Keymaker::gen(group);

        Trustee {
            keypair,
            keymaker,
            localstore
        }
    }

    pub fn add_config<B: BulletinBoard<E, G>>(&self, cfg: &Config, board: &mut B) {
        let cfg_path = self.localstore.set_config(&cfg);
        board.add_config(&cfg_path);
    }
    
    pub fn run<B: BulletinBoard<E, G>>(&self, facts: Facts, board: &mut B) {
        let actions = facts.all_actions;
        let (self_index, trustees) =
        if let InputFact::ConfigPresent(ConfigPresent(_, _, trustees, self_t)) = facts.input_facts[facts.input_facts.len() - 1] {
            (Some(self_t), Some(trustees))
        }
        else {
            (None, None)
        };
        
        for action in actions {
            match action {
                Act::AddConfig => {

                }
                Act::CheckConfig(cfg) => {
                    println!("I Should check the config now!");
                    // FIXME validate the config somehow
                    let ss = SignedStatement::config(&cfg, &self.keypair);
                    let stmt_path = self.localstore.set_config_stmt(&action, &ss);
                    board.add_config_stmt(&stmt_path, self_index.unwrap());
                }
                Act::PostShare(cfg, cnt) => {
                    println!("I Should post my share now! (contest=[{}], self=[{}])", cnt, self_index.unwrap());
                    let share = self.share();
                    let share_h = hashing::hash(&share);
                    let ss = SignedStatement::keyshare(&cfg, &share_h, cnt, &self.keypair);
                    let share_path = self.localstore.set_share(&action, share, &ss);
                    
                    board.add_share(&share_path, cnt, self_index.unwrap());
                }
                Act::CombineShares(cfg, cnt, hs) => {
                    println!("I Should combine shares now! (contest=[{}], self=[{}])", cnt, self_index.unwrap());
                    let cfg = board.get_config(cfg).unwrap();
                    let hashes = util::clear_zeroes(&hs);
                    assert!(hashes.len() as u32 == trustees.unwrap());
                    let mut shares = Vec::with_capacity(hashes.len());
                    for (i, h) in hashes.into_iter().enumerate() {
                        let next = board.get_share(cnt, i as u32, h).unwrap();
                        // assert!(Keymaker::verify_share(&cfg.rug_group.unwrap(), &next.share, &next.proof));
                        shares.push(next.share);
                    }
                    // Keymaker::combine_pks(cfg.group)
                }
                Act::CheckPk(cfg, cnt, h1, hs) => {
                    
                }
                Act::CheckMix(cfg, cnt, t, h1, h2) => {
                    
                }
                Act::Mix(cfg, cnt, h1) => {
                    
                }
                Act::PartialDecrypt(cfg, cnt, h1) => {
                    
                }
                Act::CombineDecryptions(cfg, cnt, hs) => {
                    
                }
                Act::CheckPlaintexts(cfg, cnt, h1, hs) => {
                    
                }
            }
        }
    }

    fn share(&self) -> Keyshare<E, G> {
        let (share, proof) = self.keymaker.share();
        let encrypted_sk = self.keymaker.get_encrypted_sk();
        
        Keyshare {
            share,
            proof,
            encrypted_sk
        }
    }
}

pub struct Protocol2 <E: Element + Serialize + DeserializeOwned, 
    G: Group<E> + Serialize + DeserializeOwned,
    B: BulletinBoard<E, G>> {
    
    trustee: Trustee<E, G>,
    phantom_b: PhantomData<B>
}

impl<E: Element + Serialize + DeserializeOwned, 
    G: Group<E> + Serialize + DeserializeOwned,
    B: BulletinBoard<E, G>> 
    Protocol2<E, G, B> {

    pub fn new(trustee: Trustee<E, G>) -> Protocol2<E, G, B> {
        Protocol2 {
            trustee,
            phantom_b: PhantomData
        }
    }
    
    fn get_facts(&self, board: &B) -> Vec<InputFact> {
    
        let self_pk = self.trustee.keypair.public;
        let svs = board.get_statements();
        println!("SVerifiers: {}", svs.len());
        let mut facts: Vec<InputFact> = svs.iter()
            .map(|sv| sv.verify(board))
            .filter(|f| f.is_some())
            .map(|f| f.unwrap())
            .collect();
        
        if let Some(cfg) = board.get_config_unsafe() {
            let trustees = cfg.trustees.len();
            
            let self_pos = cfg.trustees.iter()
                .position(|s| s.to_bytes() == self_pk.to_bytes())
                .unwrap();
            let hash = hashing::hash(&cfg);
            let contests = cfg.contests;

            let f = InputFact::config_present(
                hash,
                contests,
                trustees as u32,
                self_pos as u32
            );
            facts.push(f);
        };

        facts
    }
    
    pub fn process_facts(&self, board: &B) -> Facts {
        let mut runtime = Crepe::new();
        let input_facts = self.get_facts(board);
        load_facts(&input_facts, &mut runtime);
        
        let output = runtime.run();
        Facts::new(input_facts, output)
    }

    pub fn step(&self, board: &mut B) {
        let output = self.process_facts(&board);

        output.print();

        self.trustee.run(output, board);
    }
}