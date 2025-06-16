use crate::{Event, SecretKey, Signature};
use secp256k1::{schnorr, Keypair, Message, Secp256k1, XOnlyPublicKey};
use sha2::{Digest, Sha256};

impl Event {
    /// Verify the event signature
    pub fn verify_signature(&self) -> bool {
        let secp = Secp256k1::verification_only();

        // Parse the public key
        let pubkey = match XOnlyPublicKey::from_slice(self.pubkey.as_bytes()) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        // Parse the signature
        let signature = match schnorr::Signature::from_slice(self.sig.as_bytes()) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        // Hash the serialized event
        let hash = Sha256::digest(&self.serialize());
        let message = match Message::from_digest_slice(&hash) {
            Ok(msg) => msg,
            Err(_) => return false,
        };

        // Verify the signature
        secp.verify_schnorr(&signature, &message, &pubkey).is_ok()
    }

    /// Sign the event with a secret key
    pub fn sign(&mut self, secret_key: SecretKey) -> crate::Result<()> {
        if self.tags.is_empty() {
            self.tags = crate::Tags::new();
        }

        let secp = Secp256k1::new();

        // Create keypair from secret key
        let secret_key = secp256k1::SecretKey::from_slice(secret_key.as_bytes())?;
        let keypair = Keypair::from_secret_key(&secp, &secret_key);

        // Get the x-only public key
        let (xonly_pk, _) = XOnlyPublicKey::from_keypair(&keypair);
        self.pubkey = crate::PubKey::from_bytes(xonly_pk.serialize());

        // Serialize and hash the event
        let serialized = self.serialize();
        let hash = Sha256::digest(&serialized);
        self.id = crate::ID::from_bytes(hash.into());

        // Sign the hash
        let message = Message::from_digest_slice(&hash)?;
        let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);

        // Store the signature
        self.sig = Signature::from_bytes(signature.serialize());

        Ok(())
    }
}
