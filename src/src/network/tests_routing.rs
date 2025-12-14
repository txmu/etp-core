// etp-core/src/network/tests_routing.rs

use crate::network::discovery::RoutingTable;
use crate::common::NodeInfo;
use crate::wire::frame::Frame;
use crate::wire::packet::DecryptedPacket;
use std::net::SocketAddr;

#[test]
fn test_routing_table_lookup() {
    let table = RoutingTable::new();
    
    // 模拟两个节点
    let id_a = [0xAA; 32];
    let addr_a: SocketAddr = "127.0.0.1:8001".parse().unwrap();
    
    let id_b = [0xBB; 32];
    let addr_b: SocketAddr = "192.168.1.1:9000".parse().unwrap();

    // 添加节点
    table.add_node(NodeInfo::new(id_a, addr_a));
    table.add_node(NodeInfo::new(id_b, addr_b));

    // 测试查找
    assert_eq!(table.lookup(&id_a), Some(addr_a));
    assert_eq!(table.lookup(&id_b), Some(addr_b));
    
    // 测试查找不存在的节点
    let id_unknown = [0xFF; 32];
    assert_eq!(table.lookup(&id_unknown), None);
}

#[test]
fn test_relay_frame_structure() {
    // 模拟构建一个洋葱包：外层是 Relay Frame，Payload 是内层加密数据
    let next_hop_id = [0xCC; 32];
    let inner_encrypted_data = vec![0xDE, 0xAD, 0xBE, 0xEF]; // 假设这是加密后的数据

    let frame = Frame::Relay {
        next_hop: next_hop_id,
        payload: inner_encrypted_data.clone(),
    };

    // 放入 Packet
    let mut packet = DecryptedPacket::new(0, 100);
    packet.add_frame(frame);

    // 序列化
    let bytes = packet.to_bytes().unwrap();

    // 反序列化
    let restored = DecryptedPacket::from_bytes(&bytes).unwrap();
    
    if let Frame::Relay { next_hop, payload } = &restored.frames[0] {
        assert_eq!(next_hop, &next_hop_id);
        assert_eq!(payload, &inner_encrypted_data);
    } else {
        panic!("Wrong frame type");
    }
}