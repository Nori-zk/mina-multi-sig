//! HTTP implementation of the Comms trait.

use std::{
    error::Error,
    io::{BufRead, Write},
    marker::PhantomData,
    time::Duration,
};

use async_trait::async_trait;
use eyre::{eyre, OptionExt};
use frost_core::{round1::SigningCommitments, round2::SignatureShare, Ciphersuite, Identifier};
use rand::thread_rng;
use snow::{HandshakeState, TransportState};

use crate::api::{self, SendSigningPackageArgs, Uuid};
use crate::cipher::Cipher;
use crate::client::Client;

use super::super::config::Config;
use super::Comms;

/// A Noise state.
///
/// This abstracts away some awkwardness in the `snow` crate API, which
/// requires explicitly marking the handshake as finished and switching
/// to a new state object after the first message is sent.
pub struct Noise {
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

pub struct HTTPComms<C: Ciphersuite> {
    client: Client,
    session_id: Option<Uuid>,
    access_token: Option<String>,
    args: Config<C>,
    cipher: Option<Cipher>,
    _phantom: PhantomData<C>,
}

// TODO: Improve error handling for invalid session id
impl<C> HTTPComms<C>
where
    C: Ciphersuite,
{
    pub fn new(args: &Config<C>) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            client: Client::new(format!("https://{}:{}", args.ip, args.port)),
            session_id: Uuid::parse_str(&args.session_id).ok(),
            access_token: None,
            args: args.clone(),
            cipher: None,
            _phantom: Default::default(),
        })
    }
}

#[async_trait(?Send)]
impl<C> Comms<C> for HTTPComms<C>
where
    C: Ciphersuite + 'static,
{
    async fn get_signing_package(
        &mut self,
        _input: &mut dyn BufRead,
        _output: &mut dyn Write,
        commitments: SigningCommitments<C>,
        _identifier: Identifier<C>,
    ) -> Result<SendSigningPackageArgs<C>, Box<dyn Error>> {
        let mut rng = thread_rng();

        eprintln!("Logging in...");
        let challenge = self.client.challenge().await?.challenge;

        let signature: [u8; 64] = self
            .args
            .comm_privkey
            .clone()
            .ok_or_eyre("comm_privkey must be specified")?
            .sign(challenge.as_bytes(), &mut rng)?;

        self.access_token = Some(
            self.client
                .login(&api::LoginArgs {
                    challenge,
                    pubkey: self
                        .args
                        .comm_pubkey
                        .clone()
                        .ok_or_eyre("comm_pubkey must be specified")?,
                    signature: signature.to_vec(),
                })
                .await?
                .access_token
                .to_string(),
        );

        eprintln!("Joining signing session...");
        let session_id = match self.session_id {
            Some(s) => s,
            None => {
                // Get session ID from server
                let r = self.client.list_sessions().await?;
                if r.session_ids.len() > 1 {
                    return Err(eyre!("user has more than one FROST session active; use `mina-frost-client sessions` to list them and specify the session ID with `-S`").into());
                } else if r.session_ids.is_empty() {
                    return Err(eyre!("User has no current sessions active. The Coordinator should either specify your username, or manually share the session ID which you can specify with --session_id").into());
                }
                r.session_ids[0]
            }
        };
        self.session_id = Some(session_id);

        let (Some(comm_privkey), Some(comm_coordinator_pubkey_getter)) = (
            &self.args.comm_privkey,
            &self.args.comm_coordinator_pubkey_getter,
        ) else {
            return Err(
                eyre!("comm_privkey and comm_coordinator_pubkey_getter must be specified").into(),
            );
        };

        // We need to know what is the pubkey of the coordinator in order
        // to encrypt message to them.
        let session_info = self
            .client
            .get_session_info(&api::GetSessionInfoArgs { session_id })
            .await?;

        let comm_coordinator_pubkey = comm_coordinator_pubkey_getter(&session_info.coordinator_pubkey).ok_or_eyre("The coordinator for the specified FROST session is not registered in the user's address book")?;

        let cipher = Cipher::new(comm_privkey.clone(), vec![comm_coordinator_pubkey.clone()])?;
        self.cipher = Some(cipher);
        let cipher = self.cipher.as_mut().expect("was just set");

        // Send Commitments to Server
        eprintln!("Sending commitments to coordinator...");
        let send_commitments_args = vec![commitments];
        let msg = cipher.encrypt(None, serde_json::to_vec(&send_commitments_args)?)?;
        self.client
            .send(&api::SendArgs {
                session_id,
                // Empty recipients: Coordinator
                recipients: vec![],
                msg,
            })
            .await?;

        eprint!("Waiting for coordinator to send signing package...");

        // Receive SigningPackage from Coordinator.
        // The coordinator sends a chunk count header followed by N encrypted chunks.
        // We collect all chunks, decrypt each in order, and reassemble the payload.

        // First: receive the chunk count header
        let num_chunks: u32 = loop {
            let r = self
                .client
                .receive(&api::ReceiveArgs {
                    session_id,
                    as_coordinator: false,
                })
                .await?;
            if r.msgs.is_empty() {
                tokio::time::sleep(Duration::from_secs(2)).await;
                eprint!(".");
            } else {
                let msg = cipher.decrypt(r.msgs[0].clone())?;
                let header: [u8; 4] = msg.msg.as_slice().try_into().map_err(|_| {
                    eyre::eyre!("invalid chunk count header")
                })?;
                // If there were additional messages in this batch, queue them
                // for chunk collection below.
                let remaining: Vec<_> = r.msgs[1..].to_vec();
                if !remaining.is_empty() {
                    // Process remaining messages as chunks inline
                    let mut reassembled = Vec::new();
                    let expected = u32::from_be_bytes(header) as usize;
                    let mut collected = 0;
                    for m in remaining {
                        let decrypted = cipher.decrypt(m)?;
                        reassembled.extend_from_slice(&decrypted.msg);
                        collected += 1;
                        if collected == expected {
                            break;
                        }
                    }
                    // If we still need more chunks, keep polling
                    while collected < expected {
                        let r = self
                            .client
                            .receive(&api::ReceiveArgs {
                                session_id,
                                as_coordinator: false,
                            })
                            .await?;
                        for m in r.msgs {
                            let decrypted = cipher.decrypt(m)?;
                            reassembled.extend_from_slice(&decrypted.msg);
                            collected += 1;
                            if collected == expected {
                                break;
                            }
                        }
                        if collected < expected {
                            tokio::time::sleep(Duration::from_secs(2)).await;
                            eprint!(".");
                        }
                    }
                    eprintln!("\nSigning package received ({} chunks)", collected);
                    let r: SendSigningPackageArgs<C> = serde_json::from_slice(&reassembled)?;
                    return Ok(r);
                }
                break u32::from_be_bytes(header);
            }
        };

        // Collect the expected number of chunks
        let mut reassembled = Vec::new();
        let mut collected = 0usize;
        let expected = num_chunks as usize;
        while collected < expected {
            let r = self
                .client
                .receive(&api::ReceiveArgs {
                    session_id,
                    as_coordinator: false,
                })
                .await?;
            for m in r.msgs {
                let decrypted = cipher.decrypt(m)?;
                reassembled.extend_from_slice(&decrypted.msg);
                collected += 1;
                if collected == expected {
                    break;
                }
            }
            if collected < expected {
                tokio::time::sleep(Duration::from_secs(2)).await;
                eprint!(".");
            }
        }
        eprintln!("\nSigning package received ({} chunks)", collected);

        let r: SendSigningPackageArgs<C> = serde_json::from_slice(&reassembled)?;
        Ok(r)
    }

    async fn send_signature_share(
        &mut self,
        _identifier: Identifier<C>,
        signature_share: SignatureShare<C>,
    ) -> Result<(), Box<dyn Error>> {
        let cipher = self.cipher.as_mut().expect("was just set");

        // Send signature share to Coordinator

        eprintln!("Sending signature share to coordinator...");

        let send_signature_shares_args = vec![signature_share];

        let msg = cipher.encrypt(None, serde_json::to_vec(&send_signature_shares_args)?)?;

        let _r = self
            .client
            .send(&api::SendArgs {
                session_id: self.session_id.unwrap(),
                // Empty recipients: Coordinator
                recipients: vec![],
                msg,
            })
            .await?;

        let _r = self.client.logout().await?;

        Ok(())
    }
}
