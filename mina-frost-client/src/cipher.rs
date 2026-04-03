//! Handles encryption and decryption of messages, as well as signing
//! challenges, in order to use frostd to run FROST.

use std::collections::HashMap;

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use snow::{HandshakeState, TransportState};
use thiserror::Error;
use xeddsa::{xed25519, Sign as _};
use zeroize::Zeroize;

pub use crate::api::PublicKey;
use crate::api::{self, Msg};

/// Errors returned by this module.
#[derive(Error, Debug)]
pub enum Error {
    #[error("cryptography error from snow: {0}")]
    SnowError(#[from] snow::Error),
    #[error("unknown recipient")]
    UnkownRecipient,
    #[error("unknown sender")]
    UnkownSender,
    #[error("invalid private key")]
    InvalidPrivateKey,
}

/// A communication private key.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Zeroize)]
#[serde(transparent)]
pub struct PrivateKey(
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    Vec<u8>,
);

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PrivateKey").field(&"REDACTED").finish()
    }
}

impl TryFrom<PrivateKey> for xed25519::PrivateKey {
    type Error = Error;

    fn try_from(value: PrivateKey) -> Result<Self, Self::Error> {
        Ok(xed25519::PrivateKey::from(
            &TryInto::<[u8; 32]>::try_into(value.0).map_err(|_| Error::InvalidPrivateKey)?,
        ))
    }
}

impl From<Vec<u8>> for PrivateKey {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl PrivateKey {
    /// Sign a message by converting this key to a XED25519 key and signing
    /// with it.
    pub fn sign(&self, msg: &[u8], mut rng: impl RngCore + CryptoRng) -> Result<[u8; 64], Error> {
        let key: xed25519::PrivateKey = self.clone().try_into()?;
        Ok(key.sign(msg, &mut rng))
    }
}

/// A Noise state.
///
/// This abstracts away some awkwardness in the `snow` crate API, which
/// requires explicitly marking the handshake as finished and switching
/// to a new state object after the first message is sent.
struct Noise {
    // These should ideally be a enum, but that makes the implementation much
    // more awkward so I went with easier option which is using two Options.
    // Only one of them must has a value at any given time.
    /// The handshake state; None after handshake is complete.
    handshake_state: Option<HandshakeState>,
    /// The transport state; None before handshake is complete.
    transport_state: Option<TransportState>,
}

impl Noise {
    /// Create a new Noise state from a HandshakeState created with the `snow`
    /// crate.
    pub fn new(handshake_state: HandshakeState) -> Self {
        Self {
            handshake_state: Some(handshake_state),
            transport_state: None,
        }
    }

    /// Write (i.e. encrypts) a message following the same API as `snow`'s
    /// [`HandshakeState::write_message()`] and
    /// [`TransportState::write_message()`].
    pub fn write_message(
        &mut self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, snow::Error> {
        if let Some(handshake_state) = &mut self.handshake_state {
            // This does the handshake and also writes a first message.
            let r = handshake_state.write_message(payload, message);
            // This `if`` should always be true, we do the check regardless for safety.
            if handshake_state.is_handshake_finished() {
                // Get the transport state from the handshake state and update
                // the struct accordingly.
                let handshake_state = self
                    .handshake_state
                    .take()
                    .expect("there must be a handshake state set");
                self.transport_state = Some(handshake_state.into_transport_mode()?);
            }
            r
        } else if let Some(transport_state) = &mut self.transport_state {
            transport_state.write_message(payload, message)
        } else {
            panic!("invalid state");
        }
    }

    /// Reads (i.e. decrypts) a message following the same API as `snow`'s
    /// [`HandshakeState::read_message()`] and
    /// [`TransportState::read_message()`].
    pub fn read_message(
        &mut self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, snow::Error> {
        // See comments in [`Self::write_message()`].
        if let Some(handshake_state) = &mut self.handshake_state {
            let r = handshake_state.read_message(payload, message);
            if handshake_state.is_handshake_finished() {
                let handshake_state = self
                    .handshake_state
                    .take()
                    .expect("there must be a handshake state set");
                self.transport_state = Some(handshake_state.into_transport_mode()?);
            }
            r
        } else if let Some(transport_state) = &mut self.transport_state {
            transport_state.read_message(payload, message)
        } else {
            panic!("invalid state");
        }
    }
}

/// A cipher which can encrypt and decrypt messages.
pub struct Cipher {
    send_noise_map: HashMap<PublicKey, Noise>,
    recv_noise_map: HashMap<PublicKey, Noise>,
}

impl Cipher {
    /// Generate a keypair for use with this cipher.
    pub fn generate_keypair() -> Result<(PrivateKey, PublicKey), Error> {
        let builder = snow::Builder::new(
            "Noise_K_25519_ChaChaPoly_BLAKE2s"
                .parse()
                .expect("should be a valid cipher"),
        );
        let keypair = builder.generate_keypair().map_err(Error::SnowError)?;
        Ok((PrivateKey(keypair.private), PublicKey(keypair.public)))
    }

    /// Instantiate a new cipher, with the user's private key and
    /// the public key of their peers.
    pub fn new(private_key: PrivateKey, peers_public_keys: Vec<PublicKey>) -> Result<Self, Error> {
        let mut send_noise_map = HashMap::new();
        let mut recv_noise_map = HashMap::new();
        for pubkey in peers_public_keys.iter().cloned() {
            let builder = snow::Builder::new(
                "Noise_K_25519_ChaChaPoly_BLAKE2s"
                    .parse()
                    .expect("should be a valid cipher"),
            );
            let send_noise = Noise::new(
                builder
                    .local_private_key(&private_key.0)
                    .remote_public_key(&pubkey.0)
                    .build_initiator()?,
            );
            let builder = snow::Builder::new(
                "Noise_K_25519_ChaChaPoly_BLAKE2s"
                    .parse()
                    .expect("should be a valid cipher"),
            );
            let recv_noise = Noise::new(
                builder
                    .local_private_key(&private_key.0)
                    .remote_public_key(&pubkey.0)
                    .build_responder()?,
            );
            send_noise_map.insert(pubkey.clone(), send_noise);
            recv_noise_map.insert(pubkey.clone(), recv_noise);
        }

        Ok(Self {
            send_noise_map,
            recv_noise_map,
        })
    }

    // Max plaintext bytes per Noise frame. The Noise spec caps messages at 65535 bytes.
    // Noise_K handshake overhead is 48 bytes (32 ephemeral key + 16 AEAD tag).
    // Transport mode overhead is 16 bytes (AEAD tag only).
    // We use the smaller limit (handshake) for all chunks to keep things simple.
    const MAX_CHUNK_PLAINTEXT: usize = api::MAX_MSG_SIZE - 48;

    // Encrypts a message for a given recipient. If `recipient` is None, this
    // will encrypt to the single recipient passed to [`Cipher::new()`]; if more
    // than one was passed, it will panic.
    //
    // Messages larger than a single Noise frame are split into chunks, each
    // encrypted as a separate Noise frame. The output is framed as:
    //   [4 bytes: num_chunks as u32 BE]
    //   [4 bytes: chunk_0_len as u32 BE][chunk_0_encrypted_bytes]
    //   [4 bytes: chunk_1_len as u32 BE][chunk_1_encrypted_bytes]
    //   ...
    // The first chunk carries the Noise_K handshake; subsequent chunks use
    // transport mode. The receiver must decrypt chunks in order.
    pub fn encrypt(
        &mut self,
        recipient: Option<&PublicKey>,
        msg: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        let recipient = recipient.cloned().unwrap_or_else(|| {
            if self.send_noise_map.len() == 1 {
                self.send_noise_map.keys().next().unwrap().clone()
            } else {
                panic!("no recipient specified and more than one recipient was passed to `Cipher::new()`");
            }
        });
        let noise = self
            .send_noise_map
            .get_mut(&recipient)
            .ok_or(Error::UnkownRecipient)?;

        let chunks: Vec<&[u8]> = if msg.is_empty() {
            vec![&[]]
        } else {
            msg.chunks(Self::MAX_CHUNK_PLAINTEXT).collect()
        };
        let num_chunks = chunks.len() as u32;

        let mut output = Vec::new();
        output.extend_from_slice(&num_chunks.to_be_bytes());

        let mut encrypted_buf = vec![0u8; api::MAX_MSG_SIZE];
        for chunk in chunks {
            let len = noise.write_message(chunk, &mut encrypted_buf)?;
            output.extend_from_slice(&(len as u32).to_be_bytes());
            output.extend_from_slice(&encrypted_buf[..len]);
        }

        Ok(output)
    }

    // Decrypts a message. Handles the chunked framing format produced by encrypt().
    // Note that this authenticates the `sender` in the `Msg` struct; if the
    // sender is tampered with, the message would fail to decrypt.
    pub fn decrypt(&mut self, msg: Msg) -> Result<Msg, Error> {
        let noise = self
            .recv_noise_map
            .get_mut(&msg.sender)
            .ok_or(Error::UnkownSender)?;

        let data = &msg.msg;
        if data.len() < 4 {
            return Err(Error::SnowError(snow::Error::Decrypt));
        }

        let num_chunks = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let mut cursor = 4;
        let mut plaintext = Vec::new();
        let mut decrypted_buf = vec![0u8; api::MAX_MSG_SIZE];

        for _ in 0..num_chunks {
            if cursor + 4 > data.len() {
                return Err(Error::SnowError(snow::Error::Decrypt));
            }
            let chunk_len = u32::from_be_bytes([
                data[cursor],
                data[cursor + 1],
                data[cursor + 2],
                data[cursor + 3],
            ]) as usize;
            cursor += 4;

            if cursor + chunk_len > data.len() {
                return Err(Error::SnowError(snow::Error::Decrypt));
            }
            let chunk = &data[cursor..cursor + chunk_len];
            cursor += chunk_len;

            let len = noise.read_message(chunk, &mut decrypted_buf)?;
            plaintext.extend_from_slice(&decrypted_buf[..len]);
        }

        Ok(Msg {
            sender: msg.sender,
            msg: plaintext,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mina_tx::{network_id::NetworkIdEnvelope, TransactionEnvelope};
    use mina_signer::NetworkId;

    /// Helper: create a pair of Ciphers that can talk to each other
    fn make_cipher_pair() -> (Cipher, Cipher, PublicKey, PublicKey) {
        let (privkey_a, pubkey_a) = Cipher::generate_keypair().unwrap();
        let (privkey_b, pubkey_b) = Cipher::generate_keypair().unwrap();
        let cipher_a = Cipher::new(privkey_a, vec![pubkey_b.clone()]).unwrap();
        let cipher_b = Cipher::new(privkey_b, vec![pubkey_a.clone()]).unwrap();
        (cipher_a, cipher_b, pubkey_a, pubkey_b)
    }

    // ---- Baseline: encrypt/decrypt roundtrips that must keep working ----

    #[test]
    fn test_roundtrip_small_message() {
        let (mut cipher_a, mut cipher_b, pubkey_a, pubkey_b) = make_cipher_pair();
        let original = b"hello frost".to_vec();

        let encrypted = cipher_a.encrypt(Some(&pubkey_b), original.clone()).unwrap();
        assert_ne!(encrypted, original);

        let decrypted = cipher_b
            .decrypt(Msg { sender: pubkey_a, msg: encrypted })
            .unwrap();
        assert_eq!(decrypted.msg, original);
    }

    #[test]
    fn test_roundtrip_empty_message() {
        let (mut cipher_a, mut cipher_b, pubkey_a, pubkey_b) = make_cipher_pair();
        let original = vec![];

        let encrypted = cipher_a.encrypt(Some(&pubkey_b), original.clone()).unwrap();
        let decrypted = cipher_b
            .decrypt(Msg { sender: pubkey_a, msg: encrypted })
            .unwrap();
        assert_eq!(decrypted.msg, original);
    }

    #[test]
    fn test_roundtrip_small_transaction() {
        let (mut cipher_a, mut cipher_b, pubkey_a, pubkey_b) = make_cipher_pair();

        let json = include_str!("../../mina-tx/tests/data/payment-zkapp.json");
        let envelope = TransactionEnvelope::from_str_network(
            json,
            NetworkIdEnvelope::from(NetworkId::TESTNET),
        )
        .unwrap();
        let original = envelope.serialize().unwrap();
        eprintln!("Small tx roundtrip size: {} bytes", original.len());

        let encrypted = cipher_a.encrypt(Some(&pubkey_b), original.clone()).unwrap();
        let decrypted = cipher_b
            .decrypt(Msg { sender: pubkey_a, msg: encrypted })
            .unwrap();
        assert_eq!(decrypted.msg, original);
    }

    // ---- Large messages: should pass after chunking is implemented ----

    #[test]
    fn test_roundtrip_large_deploy_transaction() {
        let (mut cipher_a, mut cipher_b, pubkey_a, pubkey_b) = make_cipher_pair();

        let json = include_str!("../../mina-tx/tests/data/deploy-v0.0.4-unsigned.json");
        let envelope = TransactionEnvelope::from_str_network(
            json,
            NetworkIdEnvelope::from(NetworkId::TESTNET),
        )
        .unwrap();
        let envelope_bytes = envelope.serialize().unwrap();

        // Simulate the hex encoding frost-core applies to message bytes in SigningPackage
        let original = hex::encode(&envelope_bytes).into_bytes();
        eprintln!("Hex-encoded deploy tx size: {} bytes", original.len());
        assert!(original.len() > api::MAX_MSG_SIZE);

        let encrypted = cipher_a
            .encrypt(Some(&pubkey_b), original.clone())
            .expect("large message encryption should succeed with chunking");
        let decrypted = cipher_b
            .decrypt(Msg { sender: pubkey_a, msg: encrypted })
            .expect("large message decryption should succeed with chunking");
        assert_eq!(decrypted.msg, original);
    }

    #[test]
    fn test_roundtrip_exactly_at_noise_limit() {
        let (mut cipher_a, mut cipher_b, pubkey_a, pubkey_b) = make_cipher_pair();
        // Just over the max single-frame plaintext to force 2 chunks
        let original = vec![0xABu8; 65488];

        let encrypted = cipher_a
            .encrypt(Some(&pubkey_b), original.clone())
            .expect("boundary message should encrypt");
        let decrypted = cipher_b
            .decrypt(Msg { sender: pubkey_a, msg: encrypted })
            .expect("boundary message should decrypt");
        assert_eq!(decrypted.msg, original);
    }

    #[test]
    fn test_roundtrip_200kb_message() {
        let (mut cipher_a, mut cipher_b, pubkey_a, pubkey_b) = make_cipher_pair();
        let original = vec![0x42u8; 200_000];

        let encrypted = cipher_a
            .encrypt(Some(&pubkey_b), original.clone())
            .expect("200KB message should encrypt with chunking");
        let decrypted = cipher_b
            .decrypt(Msg { sender: pubkey_a, msg: encrypted })
            .expect("200KB message should decrypt with chunking");
        assert_eq!(decrypted.msg, original);
    }

    // ---- Existing diagnostic tests ----

    #[test]
    fn test_encrypt_small_transaction_succeeds() {
        // A small payment-style zkapp transaction — should fit within Noise limits
        let json = include_str!("../../mina-tx/tests/data/payment-zkapp.json");
        let envelope = TransactionEnvelope::from_str_network(
            json,
            NetworkIdEnvelope::from(NetworkId::TESTNET),
        )
        .unwrap();
        let message_bytes = envelope.serialize().unwrap();

        let msg_size = message_bytes.len();
        eprintln!("Small tx serialized size: {} bytes", msg_size);
        assert!(msg_size < 65535, "small tx should be under Noise limit");

        // Verify encryption works
        let (privkey_a, pubkey_a) = Cipher::generate_keypair().unwrap();
        let (privkey_b, pubkey_b) = Cipher::generate_keypair().unwrap();

        let mut cipher_a = Cipher::new(privkey_a, vec![pubkey_b.clone()]).unwrap();
        let encrypted = cipher_a.encrypt(Some(&pubkey_b), message_bytes.clone());
        assert!(encrypted.is_ok(), "small tx encryption should succeed");
    }

    #[test]
    fn test_encrypt_deploy_v004_transaction_fails_noise_limit() {
        // The deploy-v0.0.4 transaction with verification keys is large.
        // After being wrapped in a TransactionEnvelope, serialized, then put into a
        // SigningPackage and serialized AGAIN (with hex encoding of the message bytes),
        // the payload exceeds the Noise protocol's 65535-byte message limit.
        let json = include_str!("../../mina-tx/tests/data/deploy-v0.0.4-unsigned.json");
        let envelope = TransactionEnvelope::from_str_network(
            json,
            NetworkIdEnvelope::from(NetworkId::TESTNET),
        )
        .unwrap();
        let message_bytes = envelope.serialize().unwrap();

        let msg_size = message_bytes.len();
        eprintln!("Deploy tx serialized envelope size: {} bytes", msg_size);

        // Simulate what the coordinator does: wrap in SendSigningPackageArgs and serialize.
        // The SigningPackage contains commitments + message, then gets serde_json serialized.
        // frost-core hex-encodes the message bytes, roughly doubling the size.
        // We can't easily construct a real SigningPackage here without commitments,
        // but we can check the raw envelope size and the hex-encoded size.
        let hex_encoded_size = msg_size * 2; // serdect hex encoding
        eprintln!("Estimated hex-encoded message size: {} bytes", hex_encoded_size);
        eprintln!("Noise limit: {} bytes", api::MAX_MSG_SIZE);

        // Directly test: can we encrypt a payload this size?
        let (privkey_a, _pubkey_a) = Cipher::generate_keypair().unwrap();
        let (_privkey_b, pubkey_b) = Cipher::generate_keypair().unwrap();

        let mut cipher = Cipher::new(privkey_a, vec![pubkey_b.clone()]).unwrap();

        // Try encrypting the raw envelope bytes (46KB) — this might work on its own
        let raw_result = cipher.encrypt(Some(&pubkey_b), message_bytes.clone());
        eprintln!(
            "Raw envelope encrypt ({}B): {}",
            msg_size,
            if raw_result.is_ok() { "OK" } else { "FAILED" }
        );

        // Now try a payload at the size it would be after serde_json serialization
        // of SendSigningPackageArgs (hex-encoded message + commitments + JSON overhead)
        let large_payload = vec![0u8; hex_encoded_size];
        // Need a fresh cipher since Noise_K state is consumed after first write
        let (privkey_c, _pubkey_c) = Cipher::generate_keypair().unwrap();
        let (_privkey_d, pubkey_d) = Cipher::generate_keypair().unwrap();
        let mut cipher2 = Cipher::new(privkey_c, vec![pubkey_d.clone()]).unwrap();
        let large_result = cipher2.encrypt(Some(&pubkey_d), large_payload);
        eprintln!(
            "Hex-sized payload encrypt ({}B): {}",
            hex_encoded_size,
            if large_result.is_ok() { "OK" } else { "FAILED" }
        );

        // With chunking, this now succeeds — previously it hit the Noise 65535-byte limit
        assert!(
            large_result.is_ok(),
            "Encrypting a payload the size of the hex-encoded deploy tx ({} bytes) should \
             succeed with chunking",
            hex_encoded_size
        );
    }
}
