use std::collections::HashSet;
use std::marker::PhantomData;
use std::convert::TryInto;
use std::fmt::Debug;

use serde::{Serialize};
use ed25519_dalek::PublicKey as SPublicKey;
use ed25519_dalek::{Verifier};

use crepe::crepe;

use crate::hashing::*;
use crate::hashing;
use crate::artifact::*;
use crate::statement::*;
use crate::elgamal::PublicKey;
use crate::elgamal::Ciphertext;
use crate::bb::*;
use crate::util;
use crate::arithm::Element;
use crate::group::Group;
use crate::action::Act;
use crate::util::short;
use crate::shuffler::*;

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
type OutputF = (HashSet<Do>, HashSet<ConfigOk>, HashSet<PkSharesAll>, HashSet<PkOk>, 
    HashSet<PkSharesUpTo>, HashSet<ConfigSignedUpTo>, HashSet<Contest>,
    HashSet<PkSignedUpTo>, HashSet<MixSignedUpTo>, HashSet<MixOk>, HashSet<ContestMixedUpTo>,
    HashSet<ContestMixedOk>);


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
    pub trustee: i32,
    pub contest: u32
}

impl SVerifier {
    
    fn verify<E: Element, G: Group<E>, B: BulletinBoard<E, G>>(&self, board: &B) -> Option<InputFact> {
        let statement = &self.statement.statement;
        let config = board.get_config_unsafe()?;
        
        let (pk, self_t): (SPublicKey, u32) =
        if self.trustee >= 0 {
            (config.trustees[self.trustee as usize], self.trustee.try_into().unwrap())
        } else {
            (config.ballotbox, 0)
        };
        
        let statement_hash = hashing::hash(statement);
        let verified = pk.verify(&statement_hash, &self.statement.signature);
        let config_h = util::to_u8_64(&statement.hashes[0]);
        // println!("* Verify returns: [{}] on [{:?}] from trustee [{}] for contest [{}]", verified.is_ok(), 
        //    &self.statement.statement.stype, &self.trustee, &self.contest
        //);
        
        let mixer_t = statement.trustee_aux.unwrap_or(self_t);

        match statement.stype {
            StatementType::Config => {
                self.ret(
                    InputFact::config_signed_by(config_h, self_t),
                    verified.is_ok()
                )
            },
            StatementType::Keyshare => {
                let share_h = util::to_u8_64(&statement.hashes[1]);
                self.ret(
                    InputFact::share_signed_by(config_h, self.contest, share_h, self_t),
                    verified.is_ok()
                )
            },
            StatementType::PublicKey => {
                let pk_h = util::to_u8_64(&statement.hashes[1]);
                self.ret(
                    InputFact::pk_signed_by(config_h, self.contest, pk_h, self_t),
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
                    InputFact::mix_signed_by(config_h, self.contest, mix_h, ballots_h, mixer_t, self_t),
                    verified.is_ok()
                )

            },
            StatementType::PDecryption => {
                let pdecryptions_h = util::to_u8_64(&statement.hashes[1]);
                self.ret(
                    InputFact::decryption_signed_by(config_h, self.contest, pdecryptions_h, self_t),
                    verified.is_ok()
                )

            },
            StatementType::Plaintexts => {
                let plaintexts_h = util::to_u8_64(&statement.hashes[1]);
                self.ret(
                    InputFact::plaintexts_signed_by(config_h, self.contest, plaintexts_h, self_t),
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
    fn mix_signed_by(c: ConfigHash, contest: ContestIndex, mix: MixHash, ballots: BallotsHash,
        mixer_t: TrusteeIndex, signer_t: TrusteeIndex) -> InputFact {
        
        InputFact::MixSignedBy(MixSignedBy(c, contest, mix, ballots, mixer_t, signer_t))
    }
    fn decryption_signed_by(c: ConfigHash, contest: ContestIndex, decryption: DecryptionHash, 
        trustee: TrusteeIndex) -> InputFact {
        
        InputFact::DecryptionSignedBy(DecryptionSignedBy(c, contest, decryption, trustee))
    }
    fn plaintexts_signed_by(c: ConfigHash, contest: ContestIndex, plaintexts: PlaintextsHash,
        trustee: TrusteeIndex) -> InputFact {
        
        InputFact::PlaintextsSignedBy(
            PlaintextsSignedBy(c, contest, plaintexts, trustee)
        )
    }
}
use std::fmt;
impl fmt::Debug for InputFact {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            InputFact::ConfigPresent(x) => write!(f, 
                "ConfigPresent: [contests={} trustees={} self={}] {:?}", 
                x.1, x.2, x.3, short(&x.0)),
            InputFact::ConfigSignedBy(x) => write!(f, 
                "ConfigSignedBy: [{}] for config: {:?}", 
                x.1, short(&x.0)),
            InputFact::PkShareSignedBy(x) => write!(f, 
                "PkShareSignedBy [contest={} trustee={}] for share: {:?}, for config: {:?}", 
                x.1, x.3, short(&x.2), short(&x.0)),
            InputFact::PkSignedBy(x) => write!(f, 
                "PkSignedBy [contest={} trustee={}] for pk: {:?}, for config: {:?}", 
                x.1, x.3, short(&x.2), short(&x.0)),
            
            InputFact::BallotsSigned(x) => write!(f, 
                "BallotsSigned [contest={}] [ballots={:?}] {:?}", x.1, short(&x.2), short(&x.0)),
            InputFact::MixSignedBy(x) => write!(f, 
                "MixSignedBy [contest={}] [mixer={}, signer={}] for config {:?}", 
                x.1, x.4, x.5, short(&x.0)),
            InputFact::DecryptionSignedBy(x) => write!(f, 
                "DecryptionSignedBy [contest={}] [signer={}] {:?}", 
                x.1, x.3, short(&x.0)),
            InputFact::PlaintextsSignedBy(x) => write!(f, 
                "PlaintextsSignedBy [contest={}] {:?}", 
                x.1, short(&x.0))
        }
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
    pk_shares_ok: HashSet<PkSharesAll>,
    pk_ok: HashSet<PkOk>,
    mixes_ok: HashSet<MixOk>,
    contest_up_to: HashSet<ContestMixedUpTo>
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
        let mixes_ok = f.9;
        let contest_up_to = f.10;

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
            pk_ok,
            mixes_ok,
            contest_up_to
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
            println!("* PkSharesAll {:?}", short(&f.0));
        }
        let next = &self.pk_ok;
        for f in next {
            println!("* PkOk {:?}", short(&f.0));
        }
        let next = &self.mixes_ok;
        for f in next {
            println!("* MixOk contest=[{}] mix=[{:?}], ballots=[{:?}] for config {:?}", 
            f.1, short(&f.2), short(&f.3), short(&f.0));
        }
        let next = &self.contest_up_to;
        for f in next {
            println!("* ContestMixedUpTo contest=[{}] mix=[{:?}] trustee=[{}], for config {:?}", 
            f.1, short(&f.2), f.3, short(&f.0));
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
    struct MixSignedBy(ConfigHash, ContestIndex, MixHash, BallotsHash, TrusteeIndex, TrusteeIndex);
    @input
    struct DecryptionSignedBy(ConfigHash, ContestIndex, DecryptionHash, TrusteeIndex);
    @input
    struct PlaintextsSignedBy(ConfigHash, ContestIndex, PlaintextsHash, TrusteeIndex);

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
    struct PkSharesAll(ConfigHash, ContestIndex, Hashes);
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
    // 8
    @output
    struct MixSignedUpTo(ConfigHash, ContestIndex, MixHash, BallotsHash, TrusteeIndex);
    // 9
    @output
    struct MixOk(ConfigHash, ContestIndex, MixHash, BallotsHash);
    // 10
    @output
    struct ContestMixedUpTo(ConfigHash, ContestIndex, MixHash, TrusteeIndex);
    // 11
    @output
    struct ContestMixedOk(ConfigHash, ContestIndex, MixHash);
    
    Do(Act::CheckConfig(config)) <- 
        ConfigPresent(config, _, _, self_t),
        !ConfigSignedBy(config, self_t);
    
    Do(Act::PostShare(config, contest)) <- 
        ConfigPresent(config, _, _, self_t),
        Contest(config, contest),
        ConfigOk(config),
        !PkShareSignedBy(config, contest, _, self_t);
    
    Do(Act::CombineShares(config, contest, hashes)) <- 
        PkSharesAll(config, contest, hashes),
        ConfigPresent(config, _, _, 0),
        ConfigOk(config),
        !PkSignedBy(config, contest, _, 0);

    Do(Act::CheckPk(config, contest, pk_hash, hashes)) <- 
        ConfigPresent(config, _, _, self_t),
        ConfigOk(config),
        PkSharesAll(config, contest, hashes),
        PkSignedBy(config, contest, pk_hash, 0),
        !PkSignedBy(config, contest, pk_hash, self_t);

    // mix 0
    Do(Act::Mix(config, contest, ballots_hash, pk_hash)) <- 
        PkOk(config, contest, pk_hash),
        ConfigPresent(config, _, _, 0),
        ConfigOk(config),    
        BallotsSigned(config, contest, ballots_hash),
        !MixSignedBy(config, contest, _, _, 0, 0);

    // mix n
    Do(Act::Mix(config, contest, mix_ballots_hash, pk_hash)) <- 
        PkOk(config, contest, pk_hash),
        ConfigPresent(config, _, _, self_t),
        ConfigOk(config),
        (self_t > 0),
        MixSignedBy(config, contest, mix_ballots_hash, _, self_t - 1, self_t - 1),
        MixSignedBy(config, contest, mix_ballots_hash, _, self_t - 1, self_t),
        !MixSignedBy(config, contest, _, _, self_t, self_t);
  
    // check mix 0
    Do(Act::CheckMix(config, contest, 0, mix_hash, ballots_hash, pk_hash)) <- 
        PkOk(config, contest, pk_hash),
        ConfigPresent(config, _, _, self_t),
        ConfigOk(config),    
        MixSignedBy(config, contest, mix_hash, ballots_hash, 0, 0),
        // input ballots to mix came from the ballotbox
        BallotsSigned(config, contest, ballots_hash),
        !MixSignedBy(config, contest, mix_hash, ballots_hash, 0, self_t);

    // check mix n
    Do(Act::CheckMix(config, contest, mixer_t, mix_hash, mix_ballots_hash, pk_hash)) <- 
        PkOk(config, contest, pk_hash),
        ConfigPresent(config, _, _, self_t),
        ConfigOk(config),    
        MixSignedBy(config, contest, mix_hash, mix_ballots_hash, mixer_t, _signer_t),
        (mixer_t > 0),
        // input ballots to mix came from a previous mix, thus (mixer_t - 1)
        MixSignedBy(config, contest, mix_ballots_hash, _, mixer_t - 1, _),
        !MixSignedBy(config, contest, mix_hash, mix_ballots_hash, mixer_t, self_t);
    
    Do(Act::PartialDecrypt(config, contest, mix_hash, share)) <- 
        PkOk(config, contest, _pk_hash),
        ConfigPresent(config, _n_trustees, _, self_t),
        ConfigOk(config),
        PkShareSignedBy(config, contest, share, self_t),
        ContestMixedOk(config, contest, mix_hash),
        !DecryptionSignedBy(config, contest, _, self_t);

    MixSignedUpTo(config, contest, mix_hash, ballots_hash, 0) <-
        MixSignedBy(config, contest, mix_hash, ballots_hash, _, 0);

    MixSignedUpTo(config, contest, mix_hash, ballots_hash, signer_t + 1) <-
        MixSignedUpTo(config, contest, mix_hash, ballots_hash, signer_t),
        MixSignedBy(config, contest, mix_hash, ballots_hash, _mixer_t, signer_t + 1);

    MixOk(config, contest, mix_hash, ballots_hash) <-
        ConfigPresent(config, _, total_t, _),
        ConfigOk(config),
        MixSignedUpTo(config, contest, mix_hash, ballots_hash, total_t - 1);

    ContestMixedUpTo(config, contest, mix_hash, 0) <- 
        MixOk(config, contest, mix_hash, ballots_hash),
        BallotsSigned(config, contest, ballots_hash);

    ContestMixedUpTo(config, contest, mix_hash, trustee + 1) <- 
        ContestMixedUpTo(config, contest, previous_mix_hash, trustee),
        MixOk(config, contest, mix_hash, previous_mix_hash);

    ContestMixedOk(config, contest, mix_hash) <- 
        ConfigPresent(config, _, total_t, _),
        ConfigOk(config),
        ContestMixedUpTo(config, contest, mix_hash, total_t - 1);
    
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

    PkSharesAll(config, contest, shares) <-
        ConfigPresent(config, _, total_t, _),
        ConfigOk(config),
        PkSharesUpTo(config, contest, total_t - 1, shares);

    PkOk(config, contest, pk_hash) <-
        ConfigPresent(config, _, total_t, _),
        ConfigOk(config),
        PkSignedUpTo(config, contest, pk_hash, total_t - 1);
    
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

#[cfg(test)]
mod tests {
    
    use std::fs;
    use std::path::Path;
    use ed25519_dalek::{Keypair};
    use uuid::Uuid;
    use rand::rngs::OsRng;
    
    use rug::Integer;

    use crate::hashing;
    use crate::artifact::Config;
    use crate::keymaker::Keymaker;
    use crate::rug_b::*;
    use crate::memory_bb::*;
    use crate::protocol::*;
    use crate::action::*;
    use crate::symmetric;
    
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
        let cfg = Config {
            id: id.as_bytes().clone(),
            group: group,
            contests: contests, 
            ballotbox: ballotbox_pk, 
            trustees: trustee_pks,
            phantom_e: PhantomData
        };
        
        let cfg_b = bincode::serialize(&cfg).unwrap();
        let tmp_file = util::write_tmp(cfg_b).unwrap();
        bb.add_config(&ConfigPath(tmp_file.path().to_path_buf()));
        
        let mut prot = Protocol::new(bb);
        let actions = prot.process_facts(self_pk).check_config;

        let cfg_h = hashing::hash(&cfg);
        let expected = Act::CheckConfig(cfg_h);
            
        assert!(actions[0] == expected);
        
        let ss = SignedStatement::config(&cfg_h, &trustee_kps[0]);
        let stmt_path = ls1.set_config_stmt(&expected, &ss);

        prot.board.add_config_stmt(&stmt_path, 0);
        
        let actions = prot.process_facts(self_pk).all_actions;
        assert!(actions.len() == 0);

        let ss = SignedStatement::config(&cfg_h, &trustee_kps[1]);
        let stmt_path = ls2.set_config_stmt(&expected, &ss);

        prot.board.add_config_stmt(&stmt_path, 1);
        let actions = prot.process_facts(self_pk).post_share;

        assert!(actions.len() as u32 == contests);

        let km1 = &trustee_keymakers[0];
        let km2 = &trustee_keymakers[1];
        
        let (pk1, proof1) = km1.share();
        let (pk2, proof2) = km2.share();
        let sym1 = symmetric::gen_key();
        let sym2 = symmetric::gen_key();
        let esk1 = km1.get_encrypted_sk(sym1);
        let esk2 = km2.get_encrypted_sk(sym2);
        
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
        let gr = &cfg.group.clone();
        assert!(Keymaker::verify_share(gr, &share1.share, &share1.proof));
        assert!(Keymaker::verify_share(gr, &share2.share, &share2.proof));
        
        let pk = Keymaker::combine_pks(gr, vec![share1.share, share2.share]);
        let pk_h = hashing::hash(&pk);
        let ss1 = SignedStatement::public_key(&cfg_h, &pk_h, 0, &trustee_kps[0]);
        let act = output.combine_shares[0];
        let pk_path = ls1.set_pk(&act, pk, &ss1);
        prot.board.set_pk(&pk_path, 0);

        let output = prot.process_facts(self_pk);
        assert!(output.combine_shares.len() == 0);
        assert!(output.check_pk.len() == 0);

        let output = prot.process_facts(other_pk);
        assert!(output.check_pk.len() == 1);
        let act = output.check_pk[0];

        let ss2 = SignedStatement::public_key(&cfg_h, &pk_h, 0, &trustee_kps[1]);
        let pk_stmt_path = ls2.set_pk_stmt(&act, &ss2);
        prot.board.set_pk_stmt(&pk_stmt_path, 0, 1);

        let _output = prot.process_facts(self_pk);
    }
}


use serde::de::DeserializeOwned;
use std::fs;
use generic_array::{typenum::U32, GenericArray};
use std::path::Path;
use ed25519_dalek::{Keypair};
use rand::rngs::OsRng;

use crate::keymaker::Keymaker;
use crate::localstore::*;
use crate::symmetric::gen_key;


pub struct Trustee<E: Element + Serialize + DeserializeOwned, 
    G: Group<E> + Serialize + DeserializeOwned> {

    pub keypair: Keypair,
    pub keymaker: Keymaker<E, G>,
    pub localstore: LocalStore<E, G>,
    pub symmetric: GenericArray<u8, U32>
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
        let symmetric = gen_key();

        Trustee {
            keypair,
            keymaker,
            localstore,
            symmetric
        }
    }
    
    pub fn run<B: BulletinBoard<E, G>>(&self, facts: Facts, board: &mut B) -> u32 {
        let actions = facts.all_actions;
        let ret = actions.len();
        let (self_index, trustees) =
        if let InputFact::ConfigPresent(ConfigPresent(_, _, trustees, self_t)) = facts.input_facts[facts.input_facts.len() - 1] {
            (Some(self_t), Some(trustees))
        }
        else {
            (None, None)
        };
        
        for action in actions {
            match action {
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
                Act::CombineShares(cfg_h, cnt, hs) => {
                    println!("I Should combine shares now! (contest=[{}], self=[{}])", cnt, self_index.unwrap());
                    let cfg = board.get_config(cfg_h).unwrap();
                    let hashes = util::clear_zeroes(&hs);
                    assert!(hashes.len() as u32 == trustees.unwrap());
                    let pk = self.get_pk(board, hashes, &cfg.group, cnt).unwrap();
                    let pk_h = hashing::hash(&pk);
                    let ss = SignedStatement::public_key(&cfg_h, &pk_h, cnt, &self.keypair);
                    
                    let pk_path = self.localstore.set_pk(&action, pk, &ss);
                    board.set_pk(&pk_path, cnt);
                }
                Act::CheckPk(cfg_h, cnt, pk_h, hs) => {
                    println!("I Should check pk now! (contest=[{}], self=[{}])", cnt, self_index.unwrap());
                    let cfg = board.get_config(cfg_h).unwrap();
                    let hashes = util::clear_zeroes(&hs);
                    let pk = self.get_pk(board, hashes, &cfg.group, cnt).unwrap();
                    let pk_h_ = hashing::hash(&pk);
                    assert!(pk_h == pk_h_);
                    let ss = SignedStatement::public_key(&cfg_h, &pk_h, cnt, &self.keypair);
                    
                    let pk_stmt_path = self.localstore.set_pk_stmt(&action, &ss);
                    board.set_pk_stmt(&pk_stmt_path, cnt, self_index.unwrap());
                }
                Act::Mix(cfg_h, cnt, ballots_h, pk_h) => {
                    let self_t = self_index.unwrap();
                    println!("I Should mix now! (contest=[{}], self=[{}])", cnt, self_t);
                    let cfg = board.get_config(cfg_h).unwrap();
                    
                    let ciphertexts = self.get_mix_src(board, cnt, self_t, ballots_h);
                    let pk = board.get_pk(cnt, pk_h).unwrap();
                    let group = &cfg.group;
                    let hs = generators(ciphertexts.len() + 1, group, cnt, cfg.id.to_vec());
                    let exp_hasher = &*group.exp_hasher();
                    let shuffler = Shuffler {
                        pk: &pk,
                        generators: &hs,
                        hasher: exp_hasher
                    };
                    let (e_primes, rs, perm) = shuffler.gen_shuffle(&ciphertexts);
                    let proof = shuffler.gen_proof(&ciphertexts, &e_primes, &rs, &perm);
                    // assert!(shuffler.check_proof(&proof, &ciphertexts, &e_primes));
                    let mix = Mix {
                        mixed_ballots: e_primes,
                        proof: proof
                    };
                    let mix_h = hashing::hash(&mix);
                    println!("Mix generated ballots {:?} from {:?}", short(&mix_h), short(&ballots_h));
                    let ss = SignedStatement::mix(&cfg_h, &mix_h, &ballots_h, cnt, &self.keypair, None);
                    let mix_path = self.localstore.set_mix(&action, mix, &ss);
                    board.add_mix(&mix_path, cnt, self_index.unwrap());
                }
                Act::CheckMix(cfg_h, cnt, trustee, mix_h, ballots_h, pk_h) => {
                    let cfg = board.get_config(cfg_h).unwrap();
                    println!("I should check mix now! (contest=[{}], self=[{}])", cnt, self_index.unwrap());
                    let mix = board.get_mix(cnt, trustee, mix_h).unwrap();
                    let ciphertexts = self.get_mix_src(board, cnt, trustee, ballots_h);
                    let pk = board.get_pk(cnt, pk_h).unwrap();
                    let group = &cfg.group;
                    let hs = generators(ciphertexts.len() + 1, group, cnt, cfg.id.to_vec());
                    let exp_hasher = &*group.exp_hasher();
                    let shuffler = Shuffler {
                        pk: &pk,
                        generators: &hs,
                        hasher: exp_hasher
                    };
                    let proof = mix.proof;
                    println!("Verifying shuffle {:?} with source {:?}", short(&mix_h), short(&ballots_h));
                    assert!(shuffler.check_proof(&proof, &ciphertexts, &mix.mixed_ballots));
                    let ss = SignedStatement::mix(&cfg_h, &mix_h, &ballots_h, cnt, &self.keypair, Some(trustee));
                    let mix_path = self.localstore.set_mix_stmt(&action, &ss);
                    board.add_mix_stmt(&mix_path, cnt, self_index.unwrap(), trustee);

                }
                Act::PartialDecrypt(cfg_h, cnt, mix_h, share_h) => {
                    let cfg = board.get_config(cfg_h).unwrap();
                    println!("I should partial decrypt (contest=[{}], self=[{}])", cnt, self_index.unwrap());
                    let mix = board.get_mix(cnt, (cfg.trustees.len() - 1) as u32, mix_h).unwrap();
                    let share = board.get_share(cnt, self_index.unwrap(), share_h).unwrap();
                }
                Act::CombineDecryptions(cfg_h, cnt, _hs) => {
                    let cfg = board.get_config(cfg_h).unwrap();
                    println!("I combine decryptions (contest=[{}], self=[{}])", cnt, self_index.unwrap());
                }
                Act::CheckPlaintexts(cfg_h, cnt, _h1, _hs) => {
                    let cfg = board.get_config(cfg_h).unwrap();
                    println!("I check plaintexts (contest=[{}], self=[{}])", cnt, self_index.unwrap());
                }
            }
        }

        ret as u32
    }

    // ballots may come the ballot box, or an earlier mix
    fn get_mix_src<B: BulletinBoard<E, G>>(&self, board: &B, contest: u32, 
        mixing_trustee: u32, ballots_h: Hash) -> Vec<Ciphertext<E>> {

        if mixing_trustee == 0 {
            let ballots = board.get_ballots(contest, ballots_h).unwrap();
            ballots.ciphertexts
        }
        else {
            let mix = board.get_mix(contest, mixing_trustee - 1, ballots_h).unwrap();
            mix.mixed_ballots
        }
    }
    
    fn share(&self) -> Keyshare<E, G> {
        let (share, proof) = self.keymaker.share();
        let encrypted_sk = self.keymaker.get_encrypted_sk(self.symmetric);
        
        Keyshare {
            share,
            proof,
            encrypted_sk
        }
    }

    fn get_pk<B: BulletinBoard<E, G>>(&self, board: &B, hs: Vec<Hash>, group: &G, 
        cnt: u32) -> Option<PublicKey<E, G>> {
        
        let mut shares = Vec::with_capacity(hs.len());
        for (i, h) in hs.iter().enumerate() {
            let next = board.get_share(cnt, i as u32, *h).unwrap();
            println!("*** Verifying share proof!");
            let ok = Keymaker::verify_share(group, &next.share, &next.proof);
            if ok {
                shares.push(next.share);
            }
            else { 
                break;
            }
        }
        if shares.len() == hs.len() {
            let pk = Keymaker::combine_pks(group, shares);
            Some(pk)
        }
        else {
            None
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
        let now = std::time::Instant::now();
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
        println!("Input facts derived in [{}ms]", now.elapsed().as_millis());

        facts
    }
    
    pub fn process_facts(&self, board: &B) -> Facts {
        let mut runtime = Crepe::new();
        let input_facts = self.get_facts(board);
        load_facts(&input_facts, &mut runtime);
        
        let now = std::time::Instant::now();
        let output = runtime.run();
        println!("Output facts derived in [{}ms]", now.elapsed().as_millis());
        
        Facts::new(input_facts, output)
    }

    pub fn step(&self, board: &mut B) -> u32 {
        println!("====================================== Step ======================================");
        let output = self.process_facts(&board);

        output.print();

        self.trustee.run(output, board)
    }
}