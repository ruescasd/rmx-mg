use std::collections::HashSet;

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

pub type TrusteeTotal = u32;
pub type TrusteeIndex = u32;
pub type ItemIndex = u32;

pub type ConfigHash = Hash;
pub type ShareHash = Hash;
pub type PkHash = Hash;
pub type BallotsHash = Hash;
pub type MixHash = Hash;
pub type DecryptionHash = Hash;
pub type PlaintextsHash = Hash;
type Hashes = [Hash; 10];

type SerializedHash = Vec<u8>;

use std::marker::PhantomData;

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
    
        let mut facts: Vec<Fact> = self.board.get_statements().iter()
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

            let f = Fact::config_present(
                hash,
                trustees as u32,
                self_pos as u32
            );
            facts.push(f);
        };

        facts
    }
    
    fn process_facts(&self, self_pk: SignaturePublicKey) -> HashSet<Do> {
        let mut runtime = Crepe::new();
        let facts = self.get_facts(self_pk);
        facts.into_iter().map(|f| {
            match f {
                Fact::ConfigPresent(x) => runtime.extend(&[x]),
                Fact::ConfigSignedBy(x) => runtime.extend(&[x]),
                Fact::PkShareSignedBy(x) => runtime.extend(&[x]),
                Fact::PkSignedBy(x) => runtime.extend(&[x]),
                Fact::BallotsSigned(x) => runtime.extend(&[x]),
                Fact::MixSignedBy(x) => runtime.extend(&[x]),
                Fact::DecryptionSignedBy(x) => runtime.extend(&[x]),
                Fact::PlaintextSignedBy(x) => runtime.extend(&[x])
            }
        }).count();

        let output = runtime.run();

        output.0
    }
}

fn get_facts<E: Element, G: Group<E>, B: BulletinBoard<E, G>>
    (board: &B, self_pk: SignaturePublicKey) -> Vec<Fact> {
    
    let mut facts: Vec<Fact> = board.get_statements().iter()
        .map(|sv| sv.verify(board))
        .filter(|f| f.is_some())
        .map(|f| f.unwrap())
        .collect();
    
    if let Some(cfg) = board.get_config() {
        let trustees = cfg.trustees.len();
        let self_pos = cfg.trustees.iter()
            .position(|s| s.to_bytes() == self_pk.to_bytes())
            .unwrap();
        let hash = hashing::hash(&cfg);

        let f = Fact::config_present(
            hash,
            trustees as u32,
            self_pos as u32
        );
        facts.push(f);
    };

    facts
}
fn process_facts<E: Element, G: Group<E>, B: BulletinBoard<E, G>>
    (board: &B, self_pk: SignaturePublicKey) -> HashSet<Do> {
    let mut runtime = Crepe::new();
    let facts = get_facts(board, self_pk);
    facts.into_iter().map(|f| {
        match f {
            Fact::ConfigPresent(x) => runtime.extend(&[x]),
            Fact::ConfigSignedBy(x) => runtime.extend(&[x]),
            Fact::PkShareSignedBy(x) => runtime.extend(&[x]),
            Fact::PkSignedBy(x) => runtime.extend(&[x]),
            Fact::BallotsSigned(x) => runtime.extend(&[x]),
            Fact::MixSignedBy(x) => runtime.extend(&[x]),
            Fact::DecryptionSignedBy(x) => runtime.extend(&[x]),
            Fact::PlaintextSignedBy(x) => runtime.extend(&[x])
        }
    }).count();

    let output = runtime.run();

    output.0
}

pub struct StatementV {
    pub statement: Statement,
    pub signature: Signature,
    pub statement_hash: Hash,
    pub trustee: u32,
    pub contest: u32,
}

impl StatementV {
    fn verify<E: Element, G: Group<E>, B: BulletinBoard<E, G>>(&self, board: &B) -> Option<Fact> {
        let statement = &self.statement;
        let config = board.get_config()?;
        let config_h = hashing::hash(&config);
        let pk = config.trustees[self.trustee as usize];
        let verified = pk.verify(&self.statement_hash, &self.signature);

        match statement.0 {
            StatementType::Config => {
                
                let expected = Statement::config(config_h.to_vec());
                if *statement == expected && verified.is_ok() {
                    Some(
                        Fact::config_signed_by(config_h, self.trustee)
                    )
                } else {
                    None
                }
            },
            StatementType::Keyshare => {
                let share = board.get_share(self.contest, self.trustee)?;
                let share_h = hashing::hash(&config);
                let expected = Statement::keyshare(config_h.to_vec(), self.contest, share_h.to_vec());
                None
            },
            StatementType::PublicKey => {
                None

            },
            StatementType::Ballots => {
                None

            },
            StatementType::Mix => {
                None

            },
            StatementType::PDecryption => {
                None

            },
            StatementType::Plaintexts => {
                None

            }
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
    PlaintextSignedBy(PlaintextSignedBy)
}
impl Fact {
    fn config_present(c: ConfigHash, total: TrusteeIndex, 
        self_index: TrusteeIndex) -> Fact {
        
        Fact::ConfigPresent(ConfigPresent(c, total, self_index))
    }
    fn config_signed_by(c: ConfigHash, trustee: TrusteeIndex) -> Fact {
        Fact::ConfigSignedBy(ConfigSignedBy(c, trustee))
    }
    fn share_signed_by(c: ConfigHash, contest: ItemIndex, share: ShareHash,
        trustee: TrusteeIndex) -> Fact {
        
        Fact::PkShareSignedBy(PkShareSignedBy(c, contest, share, trustee))
    }
    fn pk_signed_by(c: ConfigHash, contest: ItemIndex, pk: PkHash, 
        trustee: TrusteeIndex) -> Fact {
        
        Fact::PkSignedBy(PkSignedBy(c, contest, pk, trustee))
    }
    fn ballots_signed(c: ConfigHash, contest: ItemIndex, 
        ballots: BallotsHash) -> Fact {
        
        Fact::BallotsSigned(BallotsSigned(c, contest, ballots))
    }
    fn mix_signed_by(c: ConfigHash, contest: ItemIndex, mix: MixHash, 
        ballots: BallotsHash, trustee: TrusteeIndex) -> Fact {
        
        Fact::MixSignedBy(MixSignedBy(c, contest, mix, ballots, trustee))
    }
    fn decryption_signed_by(c: ConfigHash, contest: ItemIndex, decryption: DecryptionHash, 
        trustee: TrusteeIndex) -> Fact {
        
        Fact::DecryptionSignedBy(DecryptionSignedBy(c, contest, decryption, trustee))
    }
    fn plaintext_signed_by(c: ConfigHash, contest: ItemIndex, plaintexts: PlaintextsHash,
        decryptions: DecryptionHash, trustee: TrusteeIndex) -> Fact {
        
        Fact::PlaintextSignedBy(
            PlaintextSignedBy(c, contest, plaintexts, decryptions, trustee)
        )
    }
}

#[derive(Copy, Clone, Hash, Eq, PartialEq, Debug)]
pub enum Act {
    CheckConfig(ConfigHash),
    MakePk(ConfigHash, ItemIndex, Hashes),
    CheckPk(ConfigHash, ItemIndex, PkHash, Hashes),
    CheckMix(ConfigHash, ItemIndex, TrusteeIndex, MixHash),
    Mix(ConfigHash, ItemIndex, BallotsHash),
    PartialDecrypt(ConfigHash, ItemIndex, BallotsHash),
    CheckPlaintexts(ConfigHash, ItemIndex, MixHash, DecryptionHash)
}

crepe! {
    @input
    struct ConfigPresent(ConfigHash, TrusteeIndex, TrusteeIndex);
    @input
    struct ConfigSignedBy(ConfigHash, u32);
    @input
    struct PkShareSignedBy(ConfigHash, ItemIndex, ShareHash, TrusteeIndex);
    @input
    struct PkSignedBy(ConfigHash, ItemIndex, PkHash, TrusteeIndex);
    @input
    struct BallotsSigned(ConfigHash, ItemIndex, BallotsHash);
    @input
    struct MixSignedBy(ConfigHash, ItemIndex, MixHash, BallotsHash, TrusteeIndex);
    @input
    struct DecryptionSignedBy(ConfigHash, ItemIndex, DecryptionHash, TrusteeIndex);
    @input
    struct PlaintextSignedBy(ConfigHash, ItemIndex, PlaintextsHash, DecryptionHash, 
        TrusteeIndex);

    // 0
    @output
    struct Do(Act);
    // 1
    @output
    struct ConfigSignedUpTo(ConfigHash, u32);
    // 2
    @output
    struct ConfigOk(ConfigHash);
    // 3
    @output
    struct PkSharesUpTo(ConfigHash, ItemIndex, TrusteeIndex, Hashes);
    // 4
    @output
    struct PkSharesOk(ConfigHash, ItemIndex, Hashes);
    
    ConfigSignedUpTo(config, 1) <-
        ConfigSignedBy(config, 1);
    
    ConfigSignedUpTo(config, trustee + 1) <- 
        ConfigSignedUpTo(config, trustee),
        ConfigSignedBy(config, trustee + 1);
    
    ConfigOk(config) <- 
        ConfigSignedUpTo(config, auth_total),
        ConfigPresent(config, auth_total, _self);

    Do(Act::CheckConfig(config)) <- 
        ConfigPresent(config, _, _self),
        !ConfigSignedBy(config, _self);

    PkSharesUpTo(config, contest, 1, first) <-
        PkShareSignedBy(config, contest, share, 1),
        let first = array_make(share);

    PkSharesUpTo(config, contest, trustee + 1, shares) <- 
        PkSharesUpTo(config, contest, trustee, input_shares),
        PkShareSignedBy(config, contest, share, 1),
        let shares = array_set(input_shares, trustee + 1, share);

    PkSharesOk(config, contest, shares) <-
        PkSharesUpTo(config, contest, trustee_total, shares),
        ConfigPresent(config, trustee_total, _self),
        ConfigOk(config);

    Do(Act::MakePk(config, contest, hashes)) <- 
        PkSharesOk(config, contest, hashes),
        ConfigPresent(config, _, 1),
        ConfigOk(config);
    
    
        /* 
    Acc(x, 0) <- Next(0, value),
        let x = make_array(value);

    Acc(x, n + 1) <- Acc(a, n),
        Next(n + 1, value),
        let x = modify_array(a, n + 1, value);
    */
    
    // Do(Act::CheckPk(item)) <- Present(Ar::PK, item, _), !Present(Ar::SELF_PK_SIG, item, _);

    /*Do(Act::Mix(item, ballots)) <- 
        BallotsOk(config, item, ballots),
        AuthMe(config, 1),
        ConfigOk(config);*/
        
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
    
    use std::path::Path;
    use crepe::crepe;
    use uuid::Uuid;
    use rand_core::OsRng;
    use ed25519_dalek::Keypair;
    use tempfile::NamedTempFile;
    use rug::Integer;

    use crate::hashing;
    use crate::artifact;
    use crate::rug_b::*;
    use crate::memory_bb::*;
    use crate::protocol::*;
    use crate::action::*;
    use crate::util;
    
    #[test]
    fn test_crepe() {
        let mut csprng = OsRng;

        let mut bb = MemoryBulletinBoard::<Integer, RugGroup>::new();

        let id = Uuid::new_v4();
        let group = RugGroup::default();
        let contests = 2;
        let ballotbox_pk = Keypair::generate(&mut csprng).public; 
        let trustees = 3;
        let mut trustee_pks = Vec::with_capacity(trustees);
        
        for _ in 0..trustees {
            let keypair = Keypair::generate(&mut csprng);
            trustee_pks.push(keypair.public);
        }
        let self_pk = trustee_pks[0];
        let cfg = artifact::Config {
            id: id.as_bytes().clone(),
            rug_group: Some(group),
            contests: contests, 
            ballotbox: ballotbox_pk, 
            trustees: trustee_pks
        };
        let cfg_b = bincode::serialize(&cfg).unwrap();
        let cfg_f = util::write_to_tmp(cfg_b).unwrap();
        
        bb.add_config(&cfg_f.path().to_path_buf());
        let prot = Protocol::new(bb);
        let actions = prot.process_facts(self_pk);

        let expected = Do(
            Act::CheckConfig(hashing::hash(&cfg))
        );

        assert!(actions.contains(&expected));
        
        println!("==== actions ====");
        for action in actions {
            println!("{:?}", action.0);
        }
        println!("==== actions ====");

        /*let mut runtime = Crepe::new();
        let cfg = [1u8; 64];
        
        runtime.extend(&[ConfigPresent(cfg, 2, 1)]);
        runtime.extend(&[ConfigSignedBy(cfg, 1)]);
        runtime.extend(&[ConfigSignedBy(cfg, 2)]);
        
        let facts = runtime.run();
        let actions = facts.0;
        let config_ok = facts.2;
        
        
        println!("==== config_ok ====");
        for c in config_ok {
            println!("{:?}", c.0);
        }
        println!("==== config_ok ====");
        println!("==== actions ====");
        for action in actions {
            println!("{:?}", action.0);
        }
        println!("==== actions ====");


        */
    }
}

/*

use crate::hashing::*;

pub type TrusteeTotal = u32;
pub type TrusteeIndex = u32;
pub type ItemIndex = u32;

pub type ConfigHash = Hash;
pub type ShareHash = Hash;
pub type PkHash = Hash;
pub type BallotsHash = [u8; 64];
pub type MixHash = [u8; 64];
pub type DecryptionHash = [u8; 64];
pub type PlaintextsHash = [u8; 64];
pub type Arts = [Art;10];

use strum::Display;
use strum::EnumDiscriminants;

fn add_art(mut input: Arts, index: u32, value: Art) -> Arts {
    input[index as usize] = value;

    input
}

fn first_art(value: Art) -> Arts {
    let mut ret = [Art::Nil; 10];
    ret[0] = value;

    ret
}

#[derive(Copy, Clone, Hash, Eq, PartialEq, Debug, Display, EnumDiscriminants)]
pub enum Art {
    Nil,
    Config(ConfigHash, TrusteeTotal, TrusteeIndex),
    Pk(ConfigHash, ItemIndex, PkHash),
    Ballots(ConfigHash, ItemIndex, BallotsHash),
    Mix(ConfigHash, ItemIndex, BallotsHash, MixHash),
    Plaintexts(ConfigHash, ItemIndex, BallotsHash)
}

impl Art {
    pub fn same(&self, other: Art) -> bool {
        let stype: ArtDiscriminants = self.into();
        let otype: ArtDiscriminants = other.into();

        stype == otype
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::*;
    use crate::action::*;
    use crepe::crepe;

    crepe! {
        @input
        struct Present(Art);
        @input
        struct Signed(Art, TrusteeIndex);

        @output
        struct SignedConfigN(Art, TrusteeIndex);

        SignedConfigN(art, 0) <- Signed(art, 0),
            let Art::Config(hash, total, me) = art;

        SignedConfigN(art1, n + 1) <- 
            SignedConfigN(art1, n),
            Signed(art2, n + 1),
            let Art::Config(hash1, total1, me1) = art1,
            let Art::Config(hash2, total2, me2) = art2,
            (hash1 == hash2);



        
        // collects artifacts of the same type each signed by a different authority
        // used for collecting keyshares and decryptions
        @output
        struct SignedM(Arts, u32);

        SignedM(arts, 0) <- Signed(art, 0),
            let arts = first_art(art);

        SignedM(arts, n + 1) <- 
            SignedM(prev, n),
            Signed(art, n + 1),
            let arts = add_art(prev, n + 1, art),
            (prev[0].same(art));

    /* Acc(x, n + 1) <- Acc(a, n),
        Next(n + 1, value),
        let x = modify_array(a, n + 1, value);

        Acc(x, 0) <- Next(0, value),
        let x = make_array(value);

    Acc(x, n + 1) <- Acc(a, n),
        Next(n + 1, value),
        let x = modify_array(a, n + 1, value);*/

        /*
        // 0
        @output
        struct Do(Act);
        // 1
        @output
        struct ConfigSignedUpTo(ConfigHash, TrusteeIndex);
        // 2
        @output
        struct ConfigOk(ConfigHash);
        // 3
        @output
        struct PkSignedUpto(ConfigHash, TrusteeIndex);
        // 4
        @output
        struct PkOk(ConfigHash, TrusteeIndex);
        // 5
        @output
        struct BallotsOk(ConfigHash, ItemIndex, BallotsHash);

        // 6
        @output
        struct Acc([u32; 10], usize);
        
        @input
        struct Next(usize, u32);
        
        ConfigSignedUpTo(config, 0) <-
            ConfigSignedBy(config, _n);
        ConfigSignedUpTo(config, n) <-
            ConfigSignedBy(config, n),
            ConfigSignedUpTo(config, n - 1);
        
        ConfigOk(config) <- 
            ConfigSignedUpTo(config, n),
            TrusteeTotal(config, n);

        BallotsOk(config, item, ballots) <- 
            BallotsSigned(config, item, ballots),
            ConfigOk(config);

        Acc(x, 0) <- Next(0, value),
            let x = make_array(value);

        Acc(x, n + 1) <- Acc(a, n),
            Next(n + 1, value),
            let x = modify_array(a, n + 1, value);

        
        Do(Act::CheckConfig(config)) <- Present(Ar::CONFIG, _, _), 
            AuthMe(config, n), !ConfigSignedBy(config, n);


        @output
        struct Ho(u32, u32);
        
        Ho(z, y) <- Signed(x, y),
            let Ar2::CONFIG(z) = x;*/
        
        // Do(Act::CheckPk(item)) <- Present(Ar::PK, item, _), !Present(Ar::SELF_PK_SIG, item, _);

        /*Do(Act::Mix(item, ballots)) <- 
            BallotsOk(config, item, ballots),
            AuthMe(config, 1),
            ConfigOk(config);*/
            
    }
    
    #[test]
    fn test_crepe() {
        
        let mut runtime = Crepe::new();
        let cfg = [1u8; 64];
        /*
        let config = Art::Config(cfg, 3, 1);
        let ni = Art::Pk(cfg, 3, cfg);
        runtime.extend(&[Signed(config, 0)]);
        runtime.extend(&[Signed(config, 1)]);

        let facts = runtime.run();
        let actions: Vec<SignedM> = facts.0.iter().cloned().filter(|&i| i.1 == 1).collect();

        println!("==== actions ====");
        for action in actions {
            println!("{:?}", action.0.iter().cloned().filter(|&i| i != Art::Nil).collect::<Vec<Art>>());
        }
        println!("==== actions ====");
*/

        /*
        let mut runtime = Crepe::new();
        let cfg = [1u8; 64];
        let ballots = [2u8; 64];
        
        runtime.extend(&[TrusteeTotal(cfg, 2)]);
        runtime.extend(&[AuthMe(cfg, 1)]);
        // runtime.extend(&[ConfigSignedBy(cfg, 1)]);
        runtime.extend(&[ConfigSignedBy(cfg, 2)]); 
        
        
        // runtime.extend(&[BallotsSigned(cfg, 1, ballots)]);
        
        
        runtime.extend(&[Next(0, 1), Next(1, 2)]);
        
        let facts = runtime.run();
        let actions = facts.0;
        let config_ok = facts.2;
        let test = facts.6;
        
        
        println!("==== config_ok ====");
        for c in config_ok {
            println!("{:?}", c.0);
        }
        println!("==== config_ok ====");
        println!("==== actions ====");
        for action in actions {
            println!("{:?}", action.0);
        }
        println!("==== actions ====");


        println!("==== test ====");
        for t in test {
            let v: Vec<u32> = t.0.iter().cloned().filter(|&i| i != 0).collect();
            println!("{:?}", v);
        }
        println!("==== test ====");
        // runtime.extend(&[AuthCount(2)]);
        // runtime.extend(&[Verified(0), Verified(2), Verified(1)]);
        */
    }
}

*/