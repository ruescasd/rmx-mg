use crate::protocol::*;

// use strum::Display;

#[derive(Copy, Clone, Hash, Eq, PartialEq)]
pub enum Act {
    CheckConfig(ConfigHash),
    PostShare(ConfigHash, ContestIndex),
    CombineShares(ConfigHash, ContestIndex, Hashes),
    CheckPk(ConfigHash, ContestIndex, PkHash, Hashes),
    Mix(ConfigHash, ContestIndex, BallotsHash, PkHash),
    CheckMix(ConfigHash, ContestIndex, TrusteeIndex, MixHash, BallotsHash, PkHash),
    PartialDecrypt(ConfigHash, ContestIndex, BallotsHash),
    CombineDecryptions(ConfigHash, ContestIndex, Hashes),
    CheckPlaintexts(ConfigHash, ContestIndex, MixHash, Hashes)
}

use std::fmt;
use crate::util::{short, shortm};
impl fmt::Debug for Act {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Act::CheckConfig(cfg) => write!(f, "CheckConfig {:?}", short(cfg)),
            Act::PostShare(cfg, cnt) => write!(f, "PostShare contest=[{}] for config: {:?}", cnt, short(cfg)),
            Act::CombineShares(_cfg, cnt, hs) => write!(f, "CombineShares contest=[{}] shares: {:?}", cnt, shortm(hs)),
            Act::CheckPk(_cfg, cnt, h1, hs) => write!(f, "CheckPk contest=[{}], pk {:?} shares: {:?}", cnt, short(h1), shortm(hs)),
            Act::Mix(cfg, cnt, _bh, pk_h) => write!(f, "Mix contest=[{}] for config: {:?}", cnt, short(cfg)),
            Act::CheckMix(cfg, cnt, t, _mh, _bh, pk_h) => write!(f, "CheckMix contest=[{}], posted by trustee=[{}] for config: {:?}", cnt, t, short(cfg)),
            Act::PartialDecrypt(cfg, _cnt, _h1) => write!(f, "PartialDecrypt for config: {:?}", short(cfg)),
            Act::CombineDecryptions(cfg, _cnt, _hs) => write!(f, "CombineDecryptions for config: {:?}", short(cfg)),
            Act::CheckPlaintexts(cfg, _cnt, _h1, _hs) => write!(f, "CheckPlaintexts for config: {:?}", short(cfg))
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