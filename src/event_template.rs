use sha2::Digest;

/// represents an unsigned nostr event
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct EventTemplate {
    pub created_at: crate::Timestamp,
    pub kind: crate::Kind,
    pub tags: crate::Tags,
    pub content: String,
}

impl EventTemplate {
    /// returns a signed event with id, pubkey and sig
    pub fn finalize(self, secret_key: &crate::SecretKey) -> crate::Event {
        let pubkey = secret_key.pubkey();

        // create keypair from secret key
        let secret_key = secp256k1::SecretKey::from_secret_bytes(secret_key.0)
            .expect("should always work because SecretKey should always be valid");
        let keypair = secp256k1::Keypair::from_secret_key(&secret_key);

        // serialize and hash the event
        let serialized = self.serialize(&pubkey);
        let hash = sha2::Sha256::digest(&serialized);

        // sign the hash
        let signature = secp256k1::schnorr::sign_no_aux_rand(&hash, &keypair);

        crate::Event {
            id: crate::ID::from_bytes(hash.into()),
            pubkey,
            sig: crate::Signature::from_bytes(signature.to_byte_array()),
            kind: self.kind,
            tags: self.tags,
            created_at: self.created_at,
            content: self.content,
        }
    }

    /// serialize the event for ID computation
    pub fn serialize(&self, pubkey: &crate::PubKey) -> Vec<u8> {
        let array = serde_json::json!([
            0,
            pubkey.to_hex(),
            self.created_at.0,
            self.kind,
            self.tags,
            self.content
        ]);
        array.to_string().into_bytes()
    }
}

impl std::fmt::Display for EventTemplate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EventTemplate({}, {}, {}, {})",
            self.kind, self.created_at, self.tags, self.content
        )
    }
}
