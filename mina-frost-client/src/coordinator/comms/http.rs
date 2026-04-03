//! HTTP implementation of the Comms trait.

use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    io::{BufRead, Write},
    marker::PhantomData,
    time::Duration,
    vec,
};

use async_trait::async_trait;
use eyre::{eyre, OptionExt};
use frost_core::{
    keys::PublicKeyPackage, round1::SigningCommitments, round2::SignatureShare, Ciphersuite,
    Identifier, SigningPackage,
};
use rand::thread_rng;
use serde_json;

use crate::cipher::Cipher;
use crate::client::Client;
use crate::{
    api::{self, PublicKey, SendSigningPackageArgs, Uuid},
    session::CoordinatorSessionState,
};

use super::super::config::Config;
use super::Comms;

pub struct HTTPComms<C: Ciphersuite> {
    client: Client,
    session_id: Option<Uuid>,
    config: Config<C>,
    state: CoordinatorSessionState<C>,
    pubkeys: HashMap<PublicKey, Identifier<C>>,
    cipher: Option<Cipher>,
    _phantom: PhantomData<C>,
}

impl<C: Ciphersuite> HTTPComms<C> {
    pub fn new(config: &Config<C>) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            client: Client::new(format!("https://{}:{}", config.ip, config.port)),
            session_id: None,
            config: config.clone(),
            state: CoordinatorSessionState::new(
                1, // Supporting just one message
                config.num_signers as usize,
                config.signers.clone(),
            ),
            pubkeys: Default::default(),
            cipher: None,
            _phantom: Default::default(),
        })
    }
}

#[async_trait(?Send)]
impl<C: Ciphersuite + 'static> Comms<C> for HTTPComms<C> {
    async fn get_signing_commitments(
        &mut self,
        _input: &mut dyn BufRead,
        _output: &mut dyn Write,
        _pub_key_package: &PublicKeyPackage<C>,
        _num_signers: u16,
    ) -> Result<BTreeMap<Identifier<C>, SigningCommitments<C>>, Box<dyn Error>> {
        let mut rng = thread_rng();

        eprintln!("Logging in...");
        let challenge = self.client.challenge().await?.challenge;

        let signature: [u8; 64] = self
            .config
            .comm_privkey
            .clone()
            .ok_or_eyre("comm_privkey must be specified")?
            .sign(challenge.as_bytes(), &mut rng)?;

        self.client
            .login(&api::LoginArgs {
                challenge,
                pubkey: self
                    .config
                    .comm_pubkey
                    .clone()
                    .ok_or_eyre("comm_pubkey must be specified")?,
                signature: signature.to_vec(),
            })
            .await?;

        eprintln!("Creating signing session...");
        let r = self
            .client
            .create_new_session(&api::CreateNewSessionArgs {
                pubkeys: self.config.signers.keys().cloned().collect(),
                message_count: 1,
            })
            .await?;

        if self.config.signers.is_empty() {
            eprintln!(
                "Send the following session ID to participants: {}",
                r.session_id
            );
        }
        self.session_id = Some(r.session_id);

        let Some(comm_privkey) = &self.config.comm_privkey else {
            return Err(eyre!("comm_privkey must be specified").into());
        };

        // If encryption is enabled, create the Noise objects

        let mut cipher = Cipher::new(
            comm_privkey.clone(),
            self.config.signers.keys().cloned().collect(),
        )?;

        eprint!("Waiting for participants to send their commitments...");

        loop {
            let r = self
                .client
                .receive(&api::ReceiveArgs {
                    session_id: r.session_id,
                    as_coordinator: true,
                })
                .await?;
            for msg in r.msgs {
                let msg = cipher.decrypt(msg)?;
                self.state.recv(msg)?;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            eprint!(".");
            if self.state.has_commitments() {
                break;
            }
        }
        eprintln!();

        self.cipher = Some(cipher);

        let (commitments, pubkeys) = self.state.commitments()?;
        self.pubkeys = pubkeys;

        // TODO: support more than 1
        Ok(commitments[0].clone())
    }

    async fn send_signing_package_and_get_signature_shares(
        &mut self,
        _input: &mut dyn BufRead,
        _output: &mut dyn Write,
        signing_package: &SigningPackage<C>,
    ) -> Result<BTreeMap<Identifier<C>, SignatureShare<C>>, Box<dyn Error>> {
        eprintln!("Sending SigningPackage to participants...");
        let cipher = self
            .cipher
            .as_mut()
            .expect("cipher must have been set before");
        let send_signing_package_config = SendSigningPackageArgs {
            signing_package: vec![signing_package.clone()],
            aux_msg: Default::default(),
        };

        // We need to send a message separately for each recipient even if the
        // message is the same, because they are (possibly) encrypted
        // individually for each recipient.
        //
        // Large payloads (e.g. deploy transactions with verification keys) may
        // exceed frostd's MAX_MSG_SIZE (65535 bytes) after JSON serialization and
        // encryption. We chunk the serialized payload so each encrypted chunk fits
        // in a single frostd message. The first message sent to each recipient is
        // a 4-byte big-endian chunk count header, followed by the encrypted chunks.
        let serialized = serde_json::to_vec(&send_signing_package_config)?;
        let max_chunk_plaintext = api::MAX_MSG_SIZE - 48; // Noise_K overhead
        let plaintext_chunks: Vec<&[u8]> = serialized.chunks(max_chunk_plaintext).collect();
        let num_chunks = plaintext_chunks.len() as u32;

        let pubkeys: Vec<_> = self.pubkeys.keys().cloned().collect();
        for recipient in pubkeys {
            // Send chunk count header (encrypted)
            let header = cipher.encrypt(
                Some(&recipient),
                num_chunks.to_be_bytes().to_vec(),
            )?;
            let _r = self
                .client
                .send(&api::SendArgs {
                    session_id: self.session_id.unwrap(),
                    recipients: vec![recipient.clone()],
                    msg: header,
                })
                .await?;

            // Send each chunk (encrypted)
            for chunk in &plaintext_chunks {
                let encrypted = cipher.encrypt(
                    Some(&recipient),
                    chunk.to_vec(),
                )?;
                let _r = self
                    .client
                    .send(&api::SendArgs {
                        session_id: self.session_id.unwrap(),
                        recipients: vec![recipient.clone()],
                        msg: encrypted,
                    })
                    .await?;
            }
        }

        eprintln!("Waiting for participants to send their SignatureShares...");

        loop {
            let r = self
                .client
                .receive(&api::ReceiveArgs {
                    session_id: self.session_id.unwrap(),
                    as_coordinator: true,
                })
                .await?;
            for msg in r.msgs {
                let msg = cipher.decrypt(msg)?;
                self.state.recv(msg)?;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            eprint!(".");
            if self.state.has_signature_shares() {
                break;
            }
        }
        eprintln!();

        let _r = self
            .client
            .close_session(&api::CloseSessionArgs {
                session_id: self.session_id.unwrap(),
            })
            .await?;

        let _r = self.client.logout().await?;

        let signature_shares = self.state.signature_shares()?;

        // TODO: support more than 1
        Ok(signature_shares[0].clone())
    }

    async fn cleanup_on_error(&mut self) -> Result<(), Box<dyn Error>> {
        if let Some(session_id) = self.session_id {
            let _r = self
                .client
                .close_session(&api::CloseSessionArgs { session_id })
                .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::api::{self, SendSigningPackageArgs};
    use crate::cipher::Cipher;
    use frost_bluepallas::keys::generate_with_dealer;
    use frost_core::keys::{IdentifierList, KeyPackage};
    use mina_tx::{
        network_id::NetworkIdEnvelope, pallas_message::PallasMessage, TransactionEnvelope,
    };
    use mina_signer::NetworkId;
    use rand::thread_rng;

    /// Helper: build serialized SendSigningPackageArgs from a transaction fixture
    fn serialize_signing_package_for_tx(tx_json: &str) -> Vec<u8> {
        let envelope = TransactionEnvelope::from_str_network(
            tx_json,
            NetworkIdEnvelope::from(NetworkId::TESTNET),
        )
        .unwrap();
        let message_bytes = envelope.serialize().unwrap();

        let mut rng = thread_rng();
        let (shares, _) = generate_with_dealer::<PallasMessage, _>(
            2,
            2,
            IdentifierList::Default,
            &mut rng,
        )
        .unwrap();
        let (id, share) = shares.iter().next().unwrap();
        let key_package = KeyPackage::try_from(share.clone()).unwrap();
        let (_nonces, commitments) =
            frost_bluepallas::round1::commit(key_package.signing_share(), &mut rng);
        let mut commitments_map = BTreeMap::new();
        commitments_map.insert(*id, commitments);

        let signing_package =
            frost_bluepallas::SigningPackage::new(commitments_map, &message_bytes);
        let send_args = SendSigningPackageArgs {
            signing_package: vec![signing_package],
            aux_msg: Default::default(),
        };
        serde_json::to_vec(&send_args).unwrap()
    }

    /// Small transaction: serialized signing package fits in a single frostd message
    #[test]
    fn test_small_tx_signing_package_fits_frostd_limit() {
        let serialized = serialize_signing_package_for_tx(include_str!(
            "../../../../mina-tx/tests/data/payment-zkapp.json"
        ));
        eprintln!("Small tx SendSigningPackageArgs: {} bytes", serialized.len());
        assert!(
            serialized.len() <= api::MAX_MSG_SIZE,
            "Small tx serialized ({} bytes) should fit in frostd limit ({})",
            serialized.len(),
            api::MAX_MSG_SIZE
        );

        // Encryption should also succeed
        let (privkey, _) = Cipher::generate_keypair().unwrap();
        let (_, pubkey) = Cipher::generate_keypair().unwrap();
        let mut cipher = Cipher::new(privkey, vec![pubkey.clone()]).unwrap();
        let encrypted = cipher.encrypt(Some(&pubkey), serialized).unwrap();
        assert!(
            encrypted.len() <= api::MAX_MSG_SIZE,
            "Small tx encrypted ({} bytes) should fit in frostd limit ({})",
            encrypted.len(),
            api::MAX_MSG_SIZE
        );
    }

    /// Deploy transaction with verification keys: serialized signing package exceeds
    /// frostd's MAX_MSG_SIZE, and encryption fails because it also exceeds Noise's
    /// frame limit. This is the bug.
    #[test]
    fn test_deploy_v004_signing_package_exceeds_frostd_limit() {
        let serialized = serialize_signing_package_for_tx(include_str!(
            "../../../../mina-tx/tests/data/deploy-v0.0.4-unsigned.json"
        ));
        eprintln!(
            "Deploy tx SendSigningPackageArgs: {} bytes (frostd limit: {})",
            serialized.len(),
            api::MAX_MSG_SIZE
        );
        assert!(
            serialized.len() > api::MAX_MSG_SIZE,
            "Deploy tx serialized ({} bytes) should exceed frostd limit ({})",
            serialized.len(),
            api::MAX_MSG_SIZE
        );

        // Encryption also fails — plaintext exceeds Noise's single-frame limit
        let (privkey, _) = Cipher::generate_keypair().unwrap();
        let (_, pubkey) = Cipher::generate_keypair().unwrap();
        let mut cipher = Cipher::new(privkey, vec![pubkey.clone()]).unwrap();
        assert!(
            cipher.encrypt(Some(&pubkey), serialized).is_err(),
            "Should fail to encrypt in a single Noise frame"
        );
    }

    /// Chunking the serialized payload, encrypting each chunk separately, and
    /// reassembling after decryption should produce the original payload.
    /// Each encrypted chunk must fit within frostd's MAX_MSG_SIZE.
    #[test]
    fn test_deploy_v004_chunked_roundtrip() {
        let serialized = serialize_signing_package_for_tx(include_str!(
            "../../../../mina-tx/tests/data/deploy-v0.0.4-unsigned.json"
        ));

        // Noise_K handshake overhead: 48 bytes (32 ephemeral + 16 AEAD tag)
        let max_chunk_plaintext = api::MAX_MSG_SIZE - 48;
        let chunks: Vec<&[u8]> = serialized.chunks(max_chunk_plaintext).collect();
        eprintln!(
            "Deploy tx: {} bytes, {} chunks (max {} bytes each)",
            serialized.len(),
            chunks.len(),
            max_chunk_plaintext
        );

        let (privkey_a, pubkey_a) = Cipher::generate_keypair().unwrap();
        let (privkey_b, pubkey_b) = Cipher::generate_keypair().unwrap();
        let mut cipher_a = Cipher::new(privkey_a, vec![pubkey_b.clone()]).unwrap();
        let mut cipher_b = Cipher::new(privkey_b, vec![pubkey_a.clone()]).unwrap();

        // Coordinator side: encrypt each chunk, verify each fits in frostd limit
        let mut encrypted_chunks = Vec::new();
        for chunk in &chunks {
            let encrypted = cipher_a
                .encrypt(Some(&pubkey_b), chunk.to_vec())
                .expect("each chunk should encrypt");
            assert!(
                encrypted.len() <= api::MAX_MSG_SIZE,
                "encrypted chunk ({} bytes) exceeds frostd limit ({})",
                encrypted.len(),
                api::MAX_MSG_SIZE
            );
            encrypted_chunks.push(encrypted);
        }

        // Participant side: decrypt each chunk, reassemble
        let mut reassembled = Vec::new();
        for encrypted in encrypted_chunks {
            let decrypted = cipher_b
                .decrypt(api::Msg {
                    sender: pubkey_a.clone(),
                    msg: encrypted,
                })
                .expect("each chunk should decrypt");
            reassembled.extend_from_slice(&decrypted.msg);
        }

        assert_eq!(reassembled, serialized);

        // Verify the reassembled bytes deserialize back correctly
        let deserialized: SendSigningPackageArgs<crate::BluePallasSuite> =
            serde_json::from_slice(&reassembled).unwrap();
        assert_eq!(deserialized.signing_package.len(), 1);
    }
}
