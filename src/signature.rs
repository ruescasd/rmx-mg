use rand_core::{OsRng, RngCore};
use sha2::Sha512;
use ed25519_dalek::Keypair;
use ed25519_dalek::Signature;
use ed25519_dalek::{Signer, PublicKey, Verifier};

#[test]
fn test_signature() {
    let mut csprng = OsRng{};
    let keypair: Keypair = Keypair::generate(&mut csprng);

    let message: &[u8] = b"This is a test of the tsunami alert system.";
    let signature: Signature = keypair.sign(message);
    assert!(keypair.verify(message, &signature).is_ok());

    let public_key: PublicKey = keypair.public;
    assert!(public_key.verify(message, &signature).is_ok());
}