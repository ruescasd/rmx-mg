trait BulletinBoard {
    fn refresh(&self);
    fn post(&self);
    fn list(&self) -> Vec<String>;
    fn get(&self, key: String) -> &[u8];
}

trait Names {
    const CONFIG: &'static str = "config.json";
    const CONFIG_STMT: &'static str = "config.stmt.json";
    const PAUSE: &'static str = "pause";
    const ERROR: &'static str = "error";

    fn config_sig(auth: u32) -> String { format!("{}/config.sig", auth).to_string() }

    fn share(contest: u32, auth: u32) -> String { format!("{}/{}/share", auth, contest).to_string() }
    fn share_stmt(contest: u32, auth: u32) -> String { format!("{}/{}/share.stmt", auth, contest).to_string() }
    fn share_sig(contest: u32, auth: u32) -> String { format!("{}/{}/share.sig", auth, contest).to_string() }

    fn public_key(contest: u32, auth: u32) -> String { format!("{}/{}/public_key", auth, contest).to_string() }
    fn public_key_stmt(contest: u32, auth: u32) -> String { format!("{}/{}/public_key.stmt", auth, contest).to_string() }
    fn public_key_sig(contest: u32, auth: u32) -> String { format!("{}/{}/public_key.sig", auth, contest).to_string() }

    fn ballots(contest: u32) -> String { format!("{}/ballots", contest).to_string() }
    fn ballots_stmt(contest: u32) -> String { format!("{}/ballots_stmt", contest).to_string() }
    fn ballots_sig(contest: u32) -> String { format!("{}/ballots_sig", contest).to_string() }
    
    fn mix(contest: u32, auth: u32) -> String { format!("{}/{}/mix", auth, contest).to_string() }
    fn mix_stmt(contest: u32, auth: u32) -> String { format!("{}/{}/mix.stmt", auth, contest).to_string() }
    fn mix_sig(contest: u32, auth: u32, sign_auth: u32) -> String { format!("{}/{}/mix.{}.sig", sign_auth, contest, auth).to_string() }

    fn decryption(contest: u32, auth: u32) -> String { format!("{}/{}/decryption", auth, contest).to_string() }
    fn decryption_stmt(contest: u32, auth: u32) -> String { format!("{}/{}/decryption.stmt", auth, contest).to_string() }
    fn decryption_sig(contest: u32, auth: u32) -> String { format!("{}/{}/decryption.sig", auth, contest).to_string() }

    fn plaintexts(contest: u32, auth: u32) -> String { format!("{}/{}/plaintexts", auth, contest).to_string() }
    fn plaintexts_stmt(contest: u32, auth: u32) -> String { format!("{}/{}/plaintexts.stmt", auth, contest).to_string() }
    fn plaintexts_sig(contest: u32, auth: u32) -> String { format!("{}/{}/plaintexts.sig", auth, contest).to_string() }
    
    
    fn auth_error(auth: u32) -> String { format!("{}/error", auth).to_string() }
}

use std::collections::HashMap;

struct MemoryBulletinBoard<'a> {
    data: HashMap<String, &'a [u8]>
}
impl MemoryBulletinBoard<'_> {
    
}


impl BulletinBoard for MemoryBulletinBoard<'_> {
    fn refresh(&self) {}
    fn post(&self) {}
    fn list(&self) -> Vec<String> {
        self.data.iter().map(|(a, _)| a.clone()).collect()
    }
    fn get(&self, key: String) -> &[u8] {
        self.data.get(&key).unwrap()
    }
}