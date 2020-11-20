use ed25519_dalek::PublicKey;
use rug::Integer;
use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
struct Config {
    id: [u8; 16],
    generator: Option<Integer>,
    modulus: Option<Integer>,
    modulus_exp: Option<Integer>,
    contests: u32, 
    ballotbox: PublicKey, 
    trustees: Vec<PublicKey>
}

#[cfg(test)]
mod tests {  
    use uuid::Uuid;
    use crate::rug_b::*;
    use crate::artifact::*;
    use rand_core::OsRng;
    use ed25519_dalek::Keypair;


    #[test]
    fn test_config_serde() {
        let mut csprng = OsRng;
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
        let cfg = Config {
            id: id.as_bytes().clone(), 
            generator: Some(group.generator),
            modulus: Some(group.modulus),
            modulus_exp: Some(group.modulus_exp),
            contests: contests, 
            ballotbox: ballotbox_pk, 
            trustees: trustee_pks
        };

        let cfg_b = bincode::serialize(&cfg).unwrap();
        let cfg_d: Config = bincode::deserialize(&cfg_b).unwrap();

        assert_eq!(cfg, cfg_d);
    }
}