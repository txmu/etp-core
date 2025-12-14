// etp-core/src/transport/tests.rs

use super::reliability::ReliabilityLayer;
use crate::wire::frame::Frame;
use std::time::Duration;
use std::thread;

#[test]
fn test_reliability_basic_flow() {
    let mut layer = ReliabilityLayer::new();

    // 1. 发送包
    let pn = layer.get_next_packet_num();
    assert_eq!(pn, 1);
    
    let frames = vec![Frame::Stream { 
        stream_id: 1, offset: 0, fin: false, data: b"data".to_vec() 
    }];
    
    // 记录发送
    layer.on_packet_sent(pn, frames.clone());
    
    // 此时队列里应该有东西 (waiting for ack)
    // 注意：ReliabilityLayer 的 sent_queue 是私有的，我们通过 get_lost_frames 间接测试
    assert!(layer.get_lost_frames().is_empty()); // 时间没到，不应超时

    // 2. 模拟收到 ACK
    layer.on_ack_frame_received(pn, &[]);
    
    // 收到 ACK 后，队列应为空。即使超时也不应该返回东西
    thread::sleep(Duration::from_millis(400)); // 等待超过默认 RTO (300ms)
    assert!(layer.get_lost_frames().is_empty());
}

#[test]
fn test_reliability_retransmission() {
    let mut layer = ReliabilityLayer::new();
    let pn = layer.get_next_packet_num();
    let frames = vec![Frame::Stream { 
        stream_id: 1, offset: 0, fin: false, data: b"important".to_vec() 
    }];

    // 1. 发送
    layer.on_packet_sent(pn, frames);

    // 2. 模拟超时 (RTO 初始 300ms)
    thread::sleep(Duration::from_millis(350));

    // 3. 检查是否检测到丢包
    let lost = layer.get_lost_frames();
    assert_eq!(lost.len(), 1);
    if let Frame::Stream { data, .. } = &lost[0] {
        assert_eq!(data, b"important");
    } else {
        panic!("Wrong frame type");
    }

    // 4. 取出后，原序号应被移除 (避免重复重传相同序号)
    assert!(layer.get_lost_frames().is_empty());
}

#[test]
fn test_reliability_recv_dedup_and_ack() {
    let mut layer = ReliabilityLayer::new();

    // 1. 收到新包 100
    let is_dup = layer.on_packet_received(100);
    assert!(!is_dup);
    assert!(layer.should_send_ack());

    // 2. 收到重复包 100
    let is_dup = layer.on_packet_received(100);
    assert!(is_dup); // 应该标记为重复

    // 3. 生成 ACK
    let ack_frame = layer.generate_ack();
    if let Frame::Ack { largest_acknowledged, .. } = ack_frame {
        assert_eq!(largest_acknowledged, 100);
    } else {
        panic!("Not ACK frame");
    }
    
    // 生成 ACK 后，状态应重置
    assert!(!layer.should_send_ack());
}