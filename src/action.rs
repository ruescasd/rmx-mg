use crate::protocol::*;

// use strum::Display;

#[derive(Copy, Clone, Hash, Eq, PartialEq)]
pub enum Act {
    AddConfig,
    CheckConfig(ConfigHash),
    PostShare(ConfigHash, ContestIndex),
    CombineShares(ConfigHash, ContestIndex, Hashes),
    CheckPk(ConfigHash, ContestIndex, PkHash, Hashes),
    Mix(ConfigHash, ContestIndex, BallotsHash),
    CheckMix(ConfigHash, ContestIndex, TrusteeIndex, MixHash, BallotsHash),
    PartialDecrypt(ConfigHash, ContestIndex, BallotsHash),
    CombineDecryptions(ConfigHash, ContestIndex, Hashes),
    CheckPlaintexts(ConfigHash, ContestIndex, MixHash, Hashes)
}

use std::fmt;
use crate::util::{short, shortm};
impl fmt::Debug for Act {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Act::AddConfig => write!(f, "AddConfig"),
            Act::CheckConfig(cfg) => write!(f, "CheckConfig {:?}", short(cfg)),
            Act::PostShare(cfg, cnt) => write!(f, "PostShare contest=[{}] for config: {:?}", cnt, short(cfg)),
            Act::CombineShares(cfg, cnt, hs) => write!(f, "CombineShares contest=[{}] shares: {:?}", cnt, shortm(hs)),
            Act::CheckPk(cfg, cnt, h1, hs) => write!(f, "CheckPk contest=[{}], pk {:?} shares: {:?}", cnt, short(h1), shortm(hs)),
            Act::CheckMix(cfg, cnt, t, h1, h2) => write!(f, "CheckMix"),
            Act::Mix(cfg, cnt, h1) => write!(f, "Mix"),
            Act::PartialDecrypt(cfg, cnt, h1) => write!(f, "PartialDecrypt"),
            Act::CombineDecryptions(cfg, cnt, hs) => write!(f, "CombineDecryptions"),
            Act::CheckPlaintexts(cfg, cnt, h1, hs) => write!(f, "CheckPlaintexts")
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