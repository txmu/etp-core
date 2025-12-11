// etp-core/src/crypto/noise.rs

use snow::{Builder, TransportState, HandshakeState};
use anyhow::{Result, anyhow};

static NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE3";

#[derive(Clone)]
pub struct KeyPair {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

impl KeyPair {
    pub fn generate() -> Self {
        let builder = Builder::new(NOISE_PATTERN.parse().unwrap());
        let keypair = builder.generate_keypair().unwrap();
        Self { public: keypair.public, private: keypair.private }
    }
}

pub enum NoiseSession {
    Handshaking(HandshakeState),
    Transport(TransportState),
}

impl NoiseSession {
    pub fn new_initiator(local_key: &KeyPair, remote_pub: &[u8]) -> Result<Self> {
        let builder = Builder::new(NOISE_PATTERN.parse()?);
        let handshake = builder.local_private_key(&local_key.private).remote_public_key(remote_pub).build_initiator()?;
        Ok(Self::Handshaking(handshake))
    }

    pub fn new_responder(local_key: &KeyPair) -> Result<Self> {
        let builder = Builder::new(NOISE_PATTERN.parse()?);
        let handshake = builder.local_private_key(&local_key.private).build_responder()?;
        Ok(Self::Handshaking(handshake))
    }

    pub fn write_handshake_message(&mut self, payload: &[u8], out_buf: &mut [u8]) -> Result<(usize, bool)> {
        match self {
            Self::Handshaking(state) => {
                let len = state.write_message(payload, out_buf)?;
                if state.is_handshake_finished() {
                    let transport = state.clone().into_transport_mode()?;
                    *self = Self::Transport(transport);
                    Ok((len, true))
                } else {
                    Ok((len, false))
                }
            },
            Self::Transport(_) => Err(anyhow!("Already in transport mode")),
        }
    }

    pub fn read_handshake_message(&mut self, in_msg: &[u8], out_payload: &mut [u8]) -> Result<(usize, bool)> {
        match self {
            Self::Handshaking(state) => {
                let len = state.read_message(in_msg, out_payload)?;
                if state.is_handshake_finished() {
                    let transport = state.clone().into_transport_mode()?;
                    *self = Self::Transport(transport);
                    Ok((len, true))
                } else {
                    Ok((len, false))
                }
            },
            Self::Transport(_) => Err(anyhow!("Already in transport mode")),
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8], out_ciphertext: &mut [u8]) -> Result<usize> {
        match self {
            Self::Transport(state) => Ok(state.write_message(plaintext, out_ciphertext)?),
            Self::Handshaking(_) => Err(anyhow!("Handshake not completed")),
        }
    }

    pub fn decrypt(&mut self, ciphertext: &[u8], out_plaintext: &mut [u8]) -> Result<usize> {
        match self {
            Self::Transport(state) => Ok(state.read_message(ciphertext, out_plaintext)?),
            Self::Handshaking(_) => Err(anyhow!("Handshake not completed")),
        }
    }
    
    /// 执行密钥轮换 (Rekey)
    /// 更新发送和接收的密钥，保证前向安全性
    pub fn rekey(&mut self) -> Result<()> {
        match self {
            Self::Transport(state) => {
                // Snow 的 rekey 逻辑：基于当前密钥派生新密钥
                state.rekey(None, None); 
                Ok(())
            },
            _ => Ok(()),
        }
    }
}