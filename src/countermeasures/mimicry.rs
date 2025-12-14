// etp-core/src/countermeasures/mimicry.rs

use rand::{Rng, thread_rng};
use byteorder::{BigEndian, WriteBytesExt};

#[derive(Debug, Clone, Copy)]
pub enum MimicryType {
    None,
    Tls13,
    Http11,
    QuicInitial,
}

/// 拟态引擎：生成具有欺骗性的协议头
pub struct MimicryEngine;

impl MimicryEngine {
    /// 生成一个伪造的但合法的 TLS 1.3 ClientHello 头部
    /// OpenGFW 会解析 SNI, ALPN, SupportedVersions
    pub fn generate_tls_client_hello(sni: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut rng = thread_rng();

        // 1. Record Layer: Handshake (22), Version TLS 1.0 (0x0301) for compatibility
        buf.extend_from_slice(&[0x16, 0x03, 0x01]);
        
        // 长度占位 (后面填)
        buf.extend_from_slice(&[0x00, 0x00]); 
        let record_start = buf.len();

        // 2. Handshake: ClientHello (1)
        buf.push(0x01);
        // Handshake Length占位
        buf.extend_from_slice(&[0x00, 0x00, 0x00]);
        let handshake_start = buf.len();

        // Version: TLS 1.2 (0x0303)
        buf.extend_from_slice(&[0x03, 0x03]);

        // Random (32 bytes)
        let mut random = [0u8; 32];
        rng.fill(&mut random);
        buf.extend_from_slice(&random);

        // Session ID (0-32 bytes) - Empty for simplicity
        buf.push(0x00);

        // Cipher Suites (Generic modern suites)
        // TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256
        buf.extend_from_slice(&[0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03]);

        // Compression Methods (0)
        buf.extend_from_slice(&[0x01, 0x00]);

        // Extensions
        let ext_len_idx = buf.len();
        buf.extend_from_slice(&[0x00, 0x00]); // Ext Length placeholder

        // Ext: SNI
        Self::write_extension_sni(&mut buf, sni);
        
        // Ext: Supported Versions (TLS 1.3)
        // 必须包含，否则 OpenGFW 可能不认为是 TLS 1.3
        buf.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);

        // Ext: ALPN (h2, http/1.1)
        buf.extend_from_slice(&[0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1']);

        // 回填长度
        let total_len = buf.len();
        let handshake_len = total_len - handshake_start;
        let record_len = total_len - record_start;
        let ext_len = total_len - ext_len_idx - 2;

        // Record Len
        buf[3] = (record_len >> 8) as u8;
        buf[4] = record_len as u8;

        // Handshake Len (u24)
        buf[6] = (handshake_len >> 16) as u8;
        buf[7] = (handshake_len >> 8) as u8;
        buf[8] = handshake_len as u8;

        // Ext Len
        buf[ext_len_idx] = (ext_len >> 8) as u8;
        buf[ext_len_idx+1] = ext_len as u8;

        buf
    }

    fn write_extension_sni(buf: &mut Vec<u8>, hostname: &str) {
        buf.extend_from_slice(&[0x00, 0x00]); // Type: Server Name
        let len_idx = buf.len();
        buf.extend_from_slice(&[0x00, 0x00]); // Length placeholder

        let list_len = hostname.len() + 3; // +3 for ListLen(2) + Type(1)
        buf.extend_from_slice(&(list_len as u16).to_be_bytes());
        buf.push(0x00); // Name Type: Hostname
        buf.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
        buf.extend_from_slice(hostname.as_bytes());

        let ext_len = buf.len() - len_idx - 2;
        buf[len_idx] = (ext_len >> 8) as u8;
        buf[len_idx+1] = ext_len as u8;
    }
}