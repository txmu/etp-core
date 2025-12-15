// src/plugin/flavors/mailbox.rs

use std::sync::Arc;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use sled::{Db, IVec};
use anyhow::{Result, anyhow, Context};
use log::{info, warn, debug, error};
use tokio::sync::mpsc;
use blake3;
use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use uuid::Uuid;

use crate::plugin::{Flavor, FlavorContext, CapabilityProvider};
use crate::NodeID;

// --- 协议常量 ---
const MAILBOX_PROTO_VER: u8 = 0x01;

// 指令集
const CMD_DEPOSIT: u8 = 0x01;      // 投递: [Ver][CMD][TargetID(32)][Payload...]
const CMD_FETCH_REQ: u8 = 0x02;    // 取件请求: [Ver][CMD][PubKey(32)][Timestamp(8)][Signature(64)]
const CMD_FETCH_RESP: u8 = 0x03;   // 取件响应: [Ver][CMD][Count(4)][Msg1][Msg2]...
const CMD_DELETE_REQ: u8 = 0x04;   // 删除请求: [Ver][CMD][PubKey(32)][Timestamp(8)][Signature(64)][KeyList...]
const CMD_ACK: u8 = 0x05;          // 通用确认: [Ver][CMD][Status]

// 配置
const MAX_MSG_SIZE: usize = 512 * 1024; // 单条消息最大 512KB
const MAX_BATCH_SIZE: usize = 10;       // 每次取件最多返回 10 条

// --- 数据结构 ---

/// 存储在 DB 中的消息结构
#[derive(Debug, Serialize, Deserialize)]
struct StoredMessage {
    sender_addr: SocketAddr, // 记录来源 IP (可选，用于审计)
    timestamp: u64,
    payload: Vec<u8>,        // 加密的消息内容
}

/// 邮件箱 Flavor 核心
pub struct MailboxFlavor {
    db: Db,
    network_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
}

impl MailboxFlavor {
    pub fn new(
        db_path: &str,
        network_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>
    ) -> Result<Arc<Self>> {
        // 使用单独的目录或 Tree 来隔离 Mailbox 数据
        let db = sled::open(db_path).context("Failed to open Mailbox DB")?;
        
        info!("MailboxFlavor initialized at {}", db_path);
        
        Ok(Arc::new(Self {
            db,
            network_tx,
        }))
    }

    // --- 内部逻辑 ---

    /// 处理投递请求
    fn handle_deposit(&self, src: SocketAddr, data: &[u8]) -> Result<()> {
        // Format: [TargetID(32)][Payload...]
        if data.len() < 32 { return Err(anyhow!("Deposit data too short")); }
        
        let target_id_bytes = &data[0..32];
        let payload = &data[32..];

        if payload.len() > MAX_MSG_SIZE {
            return Err(anyhow!("Message too large"));
        }

        // 生成存储 Key: TargetID(32) + Timestamp(8) + UUID(16)
        // 这样可以通过 TargetID 前缀扫描所有属于该用户的消息
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let uuid = Uuid::new_v4();
        
        let mut storage_key = Vec::with_capacity(32 + 8 + 16);
        storage_key.extend_from_slice(target_id_bytes);
        storage_key.extend_from_slice(&now.to_be_bytes());
        storage_key.extend_from_slice(uuid.as_bytes());

        let msg = StoredMessage {
            sender_addr: src,
            timestamp: now,
            payload: payload.to_vec(),
        };

        let storage_val = bincode::serialize(&msg)?;
        
        // 存入 Default Tree 或专用 Tree
        self.db.insert(storage_key, storage_val)?;
        
        // 发送 ACK
        self.send_ack(src, 0x00).await; // 0x00 = Success
        
        debug!("Mailbox: Stored message for {:?}", hex::encode(&target_id_bytes[0..4]));
        Ok(())
    }

    /// 处理取件请求 (需鉴权)
    fn handle_fetch(&self, src: SocketAddr, data: &[u8]) -> Result<()> {
        // Format: [PubKey(32)][Timestamp(8)][Signature(64)]
        let (node_id, _) = self.verify_auth(data)?;

        // 扫描数据库
        // 前缀为 TargetID
        let prefix = node_id;
        let mut iter = self.db.scan_prefix(&prefix);
        
        let mut batch = Vec::new();
        let mut count = 0;

        // 收集消息
        while let Some(item) = iter.next() {
            if count >= MAX_BATCH_SIZE { break; }
            let (key, val) = item?;
            
            if let Ok(msg) = bincode::deserialize::<StoredMessage>(&val) {
                // 回包格式中包含 StorageKey，以便客户端请求删除
                // Entry: [KeyLen(1)][Key][PayloadLen(4)][Payload]
                batch.push((key, msg.payload));
                count += 1;
            }
        }

        if batch.is_empty() {
            // 没有消息，发个空响应
            self.send_ack(src, 0x01).await; // 0x01 = No Messages
            return Ok(());
        }

        // 构造响应包
        // [Ver][CMD_FETCH_RESP][Count(4)]...Entries...
        let mut resp = Vec::new();
        resp.push(MAILBOX_PROTO_VER);
        resp.push(CMD_FETCH_RESP);
        resp.extend_from_slice(&(count as u32).to_be_bytes());

        for (key, payload) in batch {
            // Key
            resp.push(key.len() as u8);
            resp.extend_from_slice(&key);
            // Payload
            resp.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            resp.extend_from_slice(&payload);
        }

        self.send_raw(src, resp).await;
        info!("Mailbox: Delivered {} messages to {:?}", count, hex::encode(&node_id[0..4]));
        Ok(())
    }

    /// 处理删除请求 (需鉴权)
    fn handle_delete(&self, src: SocketAddr, data: &[u8]) -> Result<()> {
        // Format: [PubKey(32)][Ts(8)][Sig(64)] [KeyLen(1)][Key]...
        let (node_id, mut cursor) = self.verify_auth(data)?;
        
        // 解析要删除的 Key 列表
        let mut deleted_count = 0;
        let total_len = data.len();

        while cursor < total_len {
            if cursor + 1 > total_len { break; }
            let key_len = data[cursor] as usize;
            cursor += 1;
            
            if cursor + key_len > total_len { break; }
            let key_bytes = &data[cursor..cursor + key_len];
            cursor += key_len;

            // 安全检查：防止删除别人的消息
            // Key 的前 32 字节必须等于请求者的 NodeID
            if key_bytes.len() >= 32 && &key_bytes[0..32] == &node_id[..] {
                self.db.remove(key_bytes)?;
                deleted_count += 1;
            } else {
                warn!("Mailbox: Unauthorized delete attempt from {}", src);
            }
        }

        debug!("Mailbox: Deleted {} messages for {:?}", deleted_count, hex::encode(&node_id[0..4]));
        self.send_ack(src, 0x00).await;
        Ok(())
    }

    /// 验证签名并返回 NodeID 和数据游标
    /// 返回: (NodeID, CursorPositionAfterSig)
    fn verify_auth(&self, data: &[u8]) -> Result<(NodeID, usize)> {
        if data.len() < 32 + 8 + 64 {
            return Err(anyhow!("Auth data too short"));
        }

        let pub_key_bytes: [u8; 32] = data[0..32].try_into()?;
        let ts_bytes: [u8; 8] = data[32..40].try_into()?;
        let sig_bytes: [u8; 64] = data[40..104].try_into()?;

        // 1. 防重放检查 (Timestamp)
        let ts = u64::from_be_bytes(ts_bytes);
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        if now.abs_diff(ts) > 300 { // 5分钟误差
            return Err(anyhow!("Auth timestamp expired or future"));
        }

        // 2. 验签
        // 签名内容约定为: "MAILBOX_AUTH" + Timestamp
        // 这样可以防止签名被挪用到其他用途
        let verifier = VerifyingKey::from_bytes(&pub_key_bytes)
            .map_err(|_| anyhow!("Invalid PubKey"))?;
        let signature = Signature::from_bytes(&sig_bytes);
        
        let mut signed_msg = Vec::new();
        signed_msg.extend_from_slice(b"MAILBOX_AUTH");
        signed_msg.extend_from_slice(&ts_bytes);

        verifier.verify(&signed_msg, &signature)
            .map_err(|_| anyhow!("Signature verification failed"))?;

        // 3. 计算 NodeID
        let node_id: NodeID = blake3::hash(&pub_key_bytes).into();

        Ok((node_id, 104))
    }

    async fn send_ack(&self, target: SocketAddr, status: u8) {
        let resp = vec![MAILBOX_PROTO_VER, CMD_ACK, status];
        self.send_raw(target, resp).await;
    }

    async fn send_raw(&self, target: SocketAddr, data: Vec<u8>) {
        // 由于 self 是 &Self，需要 clone sender
        let tx = self.network_tx.clone();
        tokio::spawn(async move {
            let _ = tx.send((target, data)).await;
        });
    }
}

// --- 插件接口实现 ---

impl CapabilityProvider for MailboxFlavor {
    fn capability_id(&self) -> String {
        "etp.flavor.mailbox.v1".into()
    }
}

impl Flavor for MailboxFlavor {
    fn priority(&self) -> u8 {
        100 // 标准优先级
    }

    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        if data.len() < 2 || data[0] != MAILBOX_PROTO_VER {
            return false;
        }

        let cmd = data[1];
        let payload = &data[2..];

        match cmd {
            CMD_DEPOSIT => {
                if let Err(e) = self.handle_deposit(ctx.src_addr, payload) {
                    warn!("Mailbox: Deposit error: {}", e);
                }
                true
            },
            CMD_FETCH_REQ => {
                if let Err(e) = self.handle_fetch(ctx.src_addr, payload) {
                    warn!("Mailbox: Fetch error: {}", e);
                }
                true
            },
            CMD_DELETE_REQ => {
                if let Err(e) = self.handle_delete(ctx.src_addr, payload) {
                    warn!("Mailbox: Delete error: {}", e);
                }
                true
            },
            _ => false
        }
    }

    fn on_connection_open(&self, _peer: SocketAddr) {
        // Mailbox 是被动服务，不需要主动动作
    }

    fn on_connection_close(&self, _peer: SocketAddr) {}
}