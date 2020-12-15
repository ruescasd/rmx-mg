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
type OutputF = (HashSet<Do>, HashSet<ConfigOk>, HashSet<PkSharesOk>, HashSet<PkSharesUpTo>, HashSet<ConfigSignedUpTo>, HashSet<Contest>);

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
    
    fn get_facts(&self, self_pk: SignaturePublicKey) -> Vec<Fact> {
    
        let svs = self.board.get_statements();
        println!("SVerifiers: {}", svs.len());
        let mut facts: Vec<Fact> = svs.iter()
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

            let f = Fact::config_present(
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
        println!("======== Input facts [");
        let facts = self.get_facts(self_pk);
        facts.into_iter().map(|f| {
            println!("* Input fact {:?}", f);
            match f {
                Fact::ConfigPresent(x) => runtime.extend(&[x]),
                Fact::ConfigSignedBy(x) => runtime.extend(&[x]),
                Fact::PkShareSignedBy(x) => runtime.extend(&[x]),
                Fact::PkSignedBy(x) => runtime.extend(&[x]),
                Fact::BallotsSigned(x) => runtime.extend(&[x]),
                Fact::MixSignedBy(x) => runtime.extend(&[x]),
                Fact::DecryptionSignedBy(x) => runtime.extend(&[x]),
                Fact::PlaintextsSignedBy(x) => runtime.extend(&[x])
            }
        }).count();
        println!("] \n");

        println!("======== Output facts [");
        let output: OutputF = runtime.run();
        let ret = OutputFacts::new(output);
        print_facts(&ret);
        println!("] \n");

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
    config_ok: HashSet<ConfigOk>
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
            config_ok
        }
    }
}

fn print_facts(facts: &OutputFacts) {
    let next = &facts.config_ok;
    if next.len() > 0 {
        for f in next {
            println!("* ConfigOk {:?}", f.0[0..5].to_vec());
        }
        
    } else {
        println!("* No ConfigOk");
    }
    let next = &facts.all_actions;
    if next.len() > 0 {
        for f in next {
            println!("* Action {:?}", f);
        }
        
    } else {
        println!("* No Actions");
    }
}

#[derive(Debug)]
pub struct SVerifier {
    pub statement: SignedStatement,
    pub trustee: u32,
    pub contest: u32
}

impl SVerifier {
    fn verify<E: Element, G: Group<E>, B: BulletinBoard<E, G>>(&self, board: &B) -> Option<Fact> {
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
                    Fact::config_signed_by(config_h, self.trustee),
                    verified.is_ok()
                )
            },
            StatementType::Keyshare => {
                let share_h = util::to_u8_64(&statement.2[1]);
                self.ret(
                    Fact::share_signed_by(config_h, self.contest, share_h, self.trustee),
                    verified.is_ok()
                )
            },
            StatementType::PublicKey => {
                let pk_h = util::to_u8_64(&statement.2[1]);
                self.ret(
                    Fact::pk_signed_by(config_h, self.contest, pk_h, self.trustee),
                    verified.is_ok()
                )
            },
            StatementType::Ballots => {
                let ballots_h = util::to_u8_64(&statement.2[1]);
                self.ret(
                    Fact::ballots_signed(config_h, self.contest, ballots_h),
                    verified.is_ok()
                )
            },
            StatementType::Mix => {
                let mix_h = util::to_u8_64(&statement.2[1]);
                let ballots_h = util::to_u8_64(&statement.2[2]);
                self.ret(
                    Fact::mix_signed_by(config_h, self.contest, mix_h, ballots_h, self.trustee),
                    verified.is_ok()
                )

            },
            StatementType::PDecryption => {
                let pdecryptions_h = util::to_u8_64(&statement.2[1]);
                let ballots_h = util::to_u8_64(&statement.2[2]);
                self.ret(
                    Fact::decryption_signed_by(config_h, self.contest, pdecryptions_h, ballots_h, self.trustee),
                    verified.is_ok()
                )

            },
            StatementType::Plaintexts => {
                let plaintexts_h = util::to_u8_64(&statement.2[1]);
                let pdecryptions_h = util::to_u8_64(&statement.2[2]);
                self.ret(
                    Fact::plaintexts_signed_by(config_h, self.contest, plaintexts_h, pdecryptions_h, self.trustee),
                    verified.is_ok()
                )
            }
        }
    }

    fn ret(&self, fact: Fact, verified: bool) -> Option<Fact> {
        if verified {
            Some(fact)
        } else {
            None
        }
    }
}

enum Fact {
    ConfigPresent(ConfigPresent),
    ConfigSignedBy(ConfigSignedBy),
    PkShareSignedBy(PkShareSignedBy),
    PkSignedBy(PkSignedBy),
    BallotsSigned(BallotsSigned),
    MixSignedBy(MixSignedBy),
    DecryptionSignedBy(DecryptionSignedBy),
    PlaintextsSignedBy(PlaintextsSignedBy)
}
impl Fact {
    fn config_present(c: ConfigHash, cn: ContestIndex, trustees: TrusteeIndex, 
        self_index: TrusteeIndex) -> Fact {
        
        Fact::ConfigPresent(ConfigPresent(c, cn, trustees, self_index))
    }
    fn config_signed_by(c: ConfigHash, trustee: TrusteeIndex) -> Fact {
        Fact::ConfigSignedBy(ConfigSignedBy(c, trustee))
    }
    fn share_signed_by(c: ConfigHash, contest: ContestIndex, share: ShareHash,
        trustee: TrusteeIndex) -> Fact {
        
        Fact::PkShareSignedBy(PkShareSignedBy(c, contest, share, trustee))
    }
    fn pk_signed_by(c: ConfigHash, contest: ContestIndex, pk: PkHash, 
        trustee: TrusteeIndex) -> Fact {
        
        Fact::PkSignedBy(PkSignedBy(c, contest, pk, trustee))
    }
    fn ballots_signed(c: ConfigHash, contest: ContestIndex, 
        ballots: BallotsHash) -> Fact {
        
        Fact::BallotsSigned(BallotsSigned(c, contest, ballots))
    }
    fn mix_signed_by(c: ConfigHash, contest: ContestIndex, mix: MixHash, 
        ballots: BallotsHash, trustee: TrusteeIndex) -> Fact {
        
        Fact::MixSignedBy(MixSignedBy(c, contest, mix, ballots, trustee))
    }
    fn decryption_signed_by(c: ConfigHash, contest: ContestIndex, decryption: DecryptionHash, 
        ballots: BallotsHash, trustee: TrusteeIndex) -> Fact {
        
        Fact::DecryptionSignedBy(DecryptionSignedBy(c, contest, decryption, ballots, trustee))
    }
    fn plaintexts_signed_by(c: ConfigHash, contest: ContestIndex, plaintexts: PlaintextsHash,
        decryptions: DecryptionHash, trustee: TrusteeIndex) -> Fact {
        
        Fact::PlaintextsSignedBy(
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
    struct PkSharesUpTo(ConfigHash, ContestIndex, TrusteeIndex, Hashes);
    // 4
    @output
    struct ConfigSignedUpTo(ConfigHash, u32);
    // 5
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
        ConfigOk(config);
    
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
        PkShareSignedBy(config, contest, share, 1),
        let shares = array_set(input_shares, trustee + 1, share);

    PkSharesOk(config, contest, shares) <-
        PkSharesUpTo(config, contest, total_t, shares),
        ConfigPresent(config, _, total_t, _),
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
impl fmt::Debug for Fact {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Fact::ConfigPresent(x) => write!(f, "ConfigPresent: [contests={} trustees={} self={}] {:?}", x.1, x.2, x.3, x.0[0..5].to_vec()),
            Fact::ConfigSignedBy(x) => write!(f, "ConfigSignedBy: [{}] for config: {:?}", x.1, x.0[0..5].to_vec()),
            Fact::PkShareSignedBy(x) => write!(f, "PkShareSignedBy {:?}", x.0),
            Fact::PkSignedBy(x) => write!(f, "PkSignedBy {:?}", x.0),
            Fact::BallotsSigned(x) => write!(f, "BallotsSigned {:?}", x.0),
            Fact::MixSignedBy(x) => write!(f, "MixSignedBy {:?}", x.0),
            Fact::DecryptionSignedBy(x) => write!(f, "DecryptionSignedBy {:?}", x.0),
            Fact::PlaintextsSignedBy(x) => write!(f, "PlaintextsSignedBy{:?}", x.0)
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
        let ls1 = LocalStore::new(local1.to_string());

        let local2 = "/tmp/local2";
        let local_path2 = Path::new(local2);
        fs::remove_dir_all(local_path2).ok();
        fs::create_dir(local_path2).ok();
        let ls2 = LocalStore::new(local2.to_string());

        let id = Uuid::new_v4();
        let group = RugGroup::default();
        let contests = 2;
        let ballotbox_pk = Keypair::generate(&mut csprng).public; 
        let trustees = 2;
        let mut trustee_kps = Vec::with_capacity(trustees);
        let mut trustee_pks = Vec::with_capacity(trustees);
        
        for _ in 0..trustees {
            let keypair = Keypair::generate(&mut csprng);
            trustee_pks.push(keypair.public);
            trustee_kps.push(keypair);
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

        let expected = Act::CheckConfig(hashing::hash(&cfg));
            
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

        assert!(actions.len() as u32 == contests)
    }
}

