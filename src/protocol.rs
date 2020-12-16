use std::collections::HashSet;
use std::marker::PhantomData;

use serde::{Deserialize, Serialize};
use ed25519_dalek::PublicKey as SignaturePublicKey;
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
use crate::util::{s, sm};

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
    HashSet<PkSharesUpTo>, HashSet<ConfigSignedUpTo>, HashSet<Contest>);

struct Protocol<E: Element, G: Group<E>, B: BulletinBoard<E, G>> {
    board: B,
    phantom_e: PhantomData<E>,
    phantom_g: PhantomData<G>
}

impl<E: Element, G: Group<E>, B: BulletinBoard<E, G>> Protocol<E, G, B> {

    fn new(board: B) -> Protocol<E, G, B> {
        Protocol {
            board: board,
            phantom_e: PhantomData,
            phantom_g: PhantomData
        }
    }
    
    fn get_facts(&self, self_pk: SignaturePublicKey) -> Vec<InputFact> {
    
        let svs = self.board.get_statements();
        println!("SVerifiers: {}", svs.len());
        let mut facts: Vec<InputFact> = svs.iter()
            .map(|sv| sv.verify(&self.board))
            .filter(|f| f.is_some())
            .map(|f| f.unwrap())
            .collect();
        
        if let Some(cfg) = self.board.get_config() {
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
    
    fn process_facts(&self, self_pk: SignaturePublicKey) -> OutputFacts {
        let mut runtime = Crepe::new();
        let facts = self.get_facts(self_pk);
        load_facts(facts, &mut runtime);
        
        let output = runtime.run();
        let ret = OutputFacts::new(output);
        
        ret.print();

        ret
    }
}

struct OutputFacts {
    all_actions: Vec<Act>,
    check_config: Vec<Act>,
    post_share: Vec<Act>,
    combine_shares: Vec<Act>,
    check_pk: Vec<Act>,
    check_mix: Vec<Act>,
    mix: Vec<Act>,
    partial_decrypt: Vec<Act>,
    combine_decriptions: Vec<Act>,
    check_plaintexts: Vec<Act>,
    config_ok: HashSet<ConfigOk>,
    pk_shares_ok: HashSet<PkSharesOk>
}

impl OutputFacts {
    pub fn new(f: OutputF) -> OutputFacts {
        let mut all_actions = vec![];
        let mut check_config = vec![];
        let mut post_share = vec![];
        let mut combine_shares = vec![];
        let mut check_pk = vec![];
        let mut check_mix = vec![];
        let mut mix = vec![];
        let mut partial_decrypt = vec![];
        let mut combine_decriptions = vec![];
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
                Act::CombineDecryptions(..) => combine_decriptions.push(a.0),
                Act::CheckPlaintexts(..) => check_plaintexts.push(a.0)
            }  
            all_actions.push(a.0);
        }

        let config_ok = f.1;
        let pk_shares_ok = f.2;

        OutputFacts{
            all_actions,
            check_config,
            post_share,
            combine_shares,
            check_pk,
            check_mix,
            mix,
            partial_decrypt,
            combine_decriptions,
            check_plaintexts,
            config_ok,
            pk_shares_ok
        }
    }

    fn print(&self) {
        println!("======== Output facts [");
        let next = &self.config_ok;
        for f in next {
            println!("* ConfigOk {:?}", s(&f.0));
        }
        let next = &self.pk_shares_ok;
        for f in next {
            println!("* PkSharesOk {:?}", s(&f.0));
        }
        let next = &self.all_actions; 
        for f in next {
            println!("* Action {:?}", f);
        }
            
        println!("] \n");
    }
}

fn load_facts(facts: Vec<InputFact>, runtime: &mut Crepe) {
    println!("======== Input facts [");
    facts.into_iter().map(|f| {
        println!("* Input fact {:?}", f);
        match f {
            InputFact::ConfigPresent(x) => runtime.extend(&[x]),
            InputFact::ConfigSignedBy(x) => runtime.extend(&[x]),
            InputFact::PkShareSignedBy(x) => runtime.extend(&[x]),
            InputFact::PkSignedBy(x) => runtime.extend(&[x]),
            InputFact::BallotsSigned(x) => runtime.extend(&[x]),
            InputFact::MixSignedBy(x) => runtime.extend(&[x]),
            InputFact::DecryptionSignedBy(x) => runtime.extend(&[x]),
            InputFact::PlaintextsSignedBy(x) => runtime.extend(&[x])
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
        let statement = &self.statement.0;
        let config = board.get_config()?;
        let pk = config.trustees[self.trustee as usize];
        let statement_hash = hashing::hash(&self.statement.0);
        let verified = pk.verify(&statement_hash, &self.statement.1);
        let config_h = util::to_u8_64(&statement.2[0]);
        println!("* Verify returns: [{}] on [{:?}] from trustee [{}] for contest [{}]", verified.is_ok(), 
            &self.statement.0.0, &self.trustee, &self.contest
        );

        match statement.0 {
            StatementType::Config => {
                self.ret(
                    InputFact::config_signed_by(config_h, self.trustee),
                    verified.is_ok()
                )
            },
            StatementType::Keyshare => {
                let share_h = util::to_u8_64(&statement.2[1]);
                self.ret(
                    InputFact::share_signed_by(config_h, self.contest, share_h, self.trustee),
                    verified.is_ok()
                )
            },
            StatementType::PublicKey => {
                let pk_h = util::to_u8_64(&statement.2[1]);
                self.ret(
                    InputFact::pk_signed_by(config_h, self.contest, pk_h, self.trustee),
                    verified.is_ok()
                )
            },
            StatementType::Ballots => {
                let ballots_h = util::to_u8_64(&statement.2[1]);
                self.ret(
                    InputFact::ballots_signed(config_h, self.contest, ballots_h),
                    verified.is_ok()
                )
            },
            StatementType::Mix => {
                let mix_h = util::to_u8_64(&statement.2[1]);
                let ballots_h = util::to_u8_64(&statement.2[2]);
                self.ret(
                    InputFact::mix_signed_by(config_h, self.contest, mix_h, ballots_h, self.trustee),
                    verified.is_ok()
                )

            },
            StatementType::PDecryption => {
                let pdecryptions_h = util::to_u8_64(&statement.2[1]);
                let ballots_h = util::to_u8_64(&statement.2[2]);
                self.ret(
                    InputFact::decryption_signed_by(config_h, self.contest, pdecryptions_h, ballots_h, self.trustee),
                    verified.is_ok()
                )

            },
            StatementType::Plaintexts => {
                let plaintexts_h = util::to_u8_64(&statement.2[1]);
                let pdecryptions_h = util::to_u8_64(&statement.2[2]);
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
    struct ConfigSignedUpTo(ConfigHash, u32);
    // 6
    @output
    struct Contest(ConfigHash, u32);
    
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

    Contest(config, contests - 1) <-
        ConfigPresent(config, contests, _, _self);

    Contest(config, n - 1) <- Contest(config, n),
        (n > 0);
    
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
                "ConfigPresent: [contests={} trustees={} self={}] {:?}", x.1, x.2, x.3, s(&x.0)),
            InputFact::ConfigSignedBy(x) => write!(f, 
                "ConfigSignedBy: [{}] for config: {:?}", x.1, s(&x.0)),
            InputFact::PkShareSignedBy(x) => write!(f, 
                "PkShareSignedBy [contest={} trustee={}] for share: {:?}, for config: {:?}", 
                x.1, x.3, x.2[0..5].to_vec(), s(&x.0)),
            InputFact::PkSignedBy(x) => write!(f, "PkSignedBy {:?}", x.0),
            InputFact::BallotsSigned(x) => write!(f, "BallotsSigned {:?}", x.0),
            InputFact::MixSignedBy(x) => write!(f, "MixSignedBy {:?}", x.0),
            InputFact::DecryptionSignedBy(x) => write!(f, "DecryptionSignedBy {:?}", x.0),
            InputFact::PlaintextsSignedBy(x) => write!(f, "PlaintextsSignedBy{:?}", x.0)
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
        let ss1 = SignedStatement::keyshare(&cfg, share1_h, 0, &trustee_kps[0]);
        let ss2 = SignedStatement::keyshare(&cfg, share2_h, 0, &trustee_kps[1]);
        let share1_path = ls1.set_share(&act, share1, &ss1);
        let share2_path = ls2.set_share(&act, share2, &ss2);

        prot.board.add_share(&share1_path, 0, 0);
        prot.board.add_share(&share2_path, 0, 1);

        let actions = prot.process_facts(self_pk).post_share;
    }
}

