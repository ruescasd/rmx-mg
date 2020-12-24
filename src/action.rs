use std::fmt;
use serde::de::DeserializeOwned;

use crate::util::{short, shortm};
use crate::protocol::*;
use crate::bb::BulletinBoard;
use crate::group::Group;
use crate::arithm::Element;
// use strum::Display;

#[derive(Copy, Clone, Hash, Eq, PartialEq)]
pub enum Act {
    CheckConfig(ConfigHash),
    PostShare(ConfigHash, ContestIndex),
    CombineShares(ConfigHash, ContestIndex, Hashes),
    CheckPk(ConfigHash, ContestIndex, PkHash, Hashes),
    Mix(ConfigHash, ContestIndex, BallotsHash, PkHash),
    CheckMix(ConfigHash, ContestIndex, TrusteeIndex, MixHash, BallotsHash, PkHash),
    PartialDecrypt(ConfigHash, ContestIndex, BallotsHash, ShareHash),
    CombineDecryptions(ConfigHash, ContestIndex, Hashes, MixHash, Hashes),
    CheckPlaintexts(ConfigHash, ContestIndex, PlaintextsHash, Hashes, MixHash, Hashes)
}

impl Act {
    pub fn run<E: Element + DeserializeOwned, G: Group<E> + DeserializeOwned, 
        B: BulletinBoard<E, G>> (&self, facts: Facts, board: &mut B) {

        
    }
}

impl fmt::Debug for Act {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Act::CheckConfig(cfg) => write!(f, "CheckConfig {:?}", short(cfg)),
            Act::PostShare(cfg, cnt) => write!(f, "PostShare cn=[{}] cfg: {:?}", cnt, short(cfg)),
            Act::CombineShares(_cfg, cnt, hs) => write!(f, "CombineShares cn=[{}] shares: {:?}", cnt, shortm(hs)),
            Act::CheckPk(_cfg, cnt, h1, hs) => write!(f, "CheckPk cn=[{}], pk {:?} shares: {:?}", cnt, short(h1), shortm(hs)),
            Act::Mix(cfg, cnt, _bh, _pk_h) => write!(f, "Mix cn=[{}] cfg: {:?}", cnt, short(cfg)),
            Act::CheckMix(cfg, cnt, t, _mh, _bh, _pk_h) => write!(f, "CheckMix cn=[{}], posted by tr=[{}] cfg: {:?}", cnt, t, short(cfg)),
            Act::PartialDecrypt(cfg, cnt, _h1, _share_h) => write!(f, "PartialDecrypt cn=[{}] cfg: {:?}", cnt, short(cfg)),
            Act::CombineDecryptions(cfg, cnt, _hs, mix_h, share_hs) => write!(f, "CombineDecryptions cn=[{}] cfg: {:?}", cnt, short(cfg)),
            Act::CheckPlaintexts(cfg, cnt, p_h, d_hs, mix_h, share_hs) => write!(f, "CheckPlaintexts cn=[{}] cfg: {:?}", cnt, short(cfg))
        }
    }
}
/* 
See https://github.com/rust-lang/rfcs/pull/2593

trait Action{}
impl Action for AddConfig{}

impl Act {
    fn typed<T: Action>(&self) -> T {
        AddConfig as T
    }
}

struct AddConfig;

struct CheckConfig {
    pub config_hash: ConfigHash
}
struct PostShare {
    pub config_hash: ConfigHash,
    pub contest: ContestIndex
}
struct CombineShares {
    pub config_hash: ConfigHash,
    pub contest: ContestIndex,
    pub hashes: Hashes
}
struct CheckPk {
    pub config_hash: ConfigHash,
    pub contest: ContestIndex,
    pub hashes: Hashes
}
struct CheckMix {
    pub config_hash: ConfigHash,
    pub contest: ContestIndex,
    pub trustee: TrusteeIndex,
    pub mix_hash: MixHash,
    // this could be a previous mix or the first ballots
    pub ballots_hash: BallotsHash
}
struct Mix {
    pub config_hash: ConfigHash,
    pub contest: ContestIndex,
    // this could be a previous mix or the first ballots
    pub ballots_hash: BallotsHash
}
struct PartialDecrypt {
    pub config_hash: ConfigHash,
    pub contest: ContestIndex,
    pub ballots_hash: BallotsHash
}
struct CombineDecryptions {
    pub config_hash: ConfigHash,
    pub contest: ContestIndex,
    pub pdecryptions: Hashes
}
struct CheckPlaintexts {
    pub config_hash: ConfigHash,
    pub contest: ContestIndex,
    pub last_mix_hash: MixHash,
    pub pdecryptions: Hashes
}
*/