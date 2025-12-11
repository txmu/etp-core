// 文件: etp-core/src/wire/tests.rs

use super::frame::{Frame, InjectionCommand};
use super::packet::{DecryptedPacket, RawPacket};
use crate::crypto::noise::{NoiseSession, KeyPair}; // 新增引入

#[test]
fn test_packet_serialization() {
    println!("Starting serialization test...");
    
    // 1. 创建逻辑包
    let mut packet = DecryptedPacket::new(1001, 1);
    
    packet.add_frame(Frame::Stream { 
        stream_id: 1, 
        offset: 0, 
        fin: false, 
        data: b"Hello ETP".to_vec() 
    });

    packet.add_frame(Frame::Injection {
        target_session: 1001,
        injector_id: [0u8; 32],
        command: InjectionCommand::Throttle { limit_kbps: 50, duration_sec: 10 },
        signature: [0xFF; 64],
    });

    // 2. 验证逻辑层序列化
    let bytes = packet.to_bytes().expect("Serialization failed");
    println!("Serialized logic packet size: {} bytes", bytes.len());

    let restored = DecryptedPacket::from_bytes(&bytes).expect("Deserialization failed");
    
    assert_eq!(restored.session_id, 1001);
    assert_eq!(restored.frames.len(), 2);
    println!("Test Passed: Logical Packet structure is valid.");
}

#[test]
fn test_packet_encryption_and_padding() {
    println!("Starting encryption and padding test...");

    // 为了测试 RawPacket，我们需要一个真实的加密会话
    let keys = KeyPair::generate();
    // 创建一个自环的 Initiator 用于加密测试
    let mut session = NoiseSession::new_initiator(&keys, &keys.public).unwrap();

    let logic = DecryptedPacket::new(999, 2);
    
    // 设定目标大小为 256 字节
    let target_size = 256;
    
    // 使用新的 encrypt_and_seal API
    let raw = RawPacket::encrypt_and_seal(&logic, &mut session, Some(target_size)).unwrap();
    
    // 预期长度 = 16 (Header混淆) + target_size (密文区，含Padding) + 16 (Poly1305 Tag)
    // 注意：我们在 implementation 里是把 Padding 加在明文里的，所以:
    // 明文长度 = target_size
    // 密文长度 = target_size + 16 (Tag)
    // 最终长度 = 16 (Header) + target_size + 16 (Tag) = target_size + 32
    let expected_len = 16 + target_size + 16;
    
    println!("Raw packet len: {}, Expected: {}", raw.data.len(), expected_len);
    
    assert_eq!(raw.data.len(), expected_len, "Packet size does not match Obfuscation rules");
}