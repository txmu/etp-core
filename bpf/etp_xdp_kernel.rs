// bpf/etp_xdp_kernel.rs
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, Ipv6Hdr, IpProto},
    udp::UdpHdr,
};

/// 配置索引
const CONFIG_SETTING_PORT: u32 = 0;
const CONFIG_SETTING_FLAGS: u32 = 1;
const CONFIG_CURRENT_UNIX_SEC: u32 = 2;

/// Flags 位掩码
const FLAG_ACL_ENABLED: u32 = 1 << 0;
const FLAG_DROP_ALL_OTHERS: u32 = 1 << 1; // 严苛模式：非 ETP 包全部丢弃

/// [核心令牌表] - 用户态必须负责过期条目的清理
#[map(name = "ETP_ALLOWED_TOKENS")]
static mut ALLOWED_TOKENS: HashMap<[u8; 32], u64> = HashMap::with_max_entries(4096, 0);

/// [全局参数表]
#[map(name = "ETP_GLOBAL_CONFIG")]
static mut ETP_GLOBAL_CONFIG: HashMap<u32, u32> = HashMap::with_max_entries(16, 0);

/// [ACL IP表] - 存储 16 字节对齐的 IP 地址
#[map(name = "ETP_IP_WHITELIST")]
static mut ETP_IP_WHITELIST: HashMap<[u8; 16], u8> = HashMap::with_max_entries(8192, 0);

#[xdp]
pub fn etp_ingress_filter(ctx: XdpContext) -> u32 {
    match try_etp_ingress_filter(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn try_etp_ingress_filter(ctx: &XdpContext) -> Result<u32, ()> {
    let mut offset = 0;
    let eth = ptr_at::<EthHdr>(ctx, offset)?;
    offset += EthHdr::LEN;

    let mut etype = unsafe { (*eth).ether_type };

    // 支持单层 VLAN 穿透解析 (0x8100)
    if etype == u16::to_be(0x8100) {
        let vlan_hdr_len = 4;
        if ctx.data() + offset + vlan_hdr_len > ctx.data_end() { return Err(()); }
        // 读取 VLAN 后的真实 EtherType
        let next_etype_ptr = (ctx.data() + offset - 2) as *const u16;
        etype = unsafe { *next_etype_ptr };
        offset += vlan_hdr_len;
    }

    let mut src_ip = [0u8; 16];

    // 1. 三层解析
    match etype {
        EtherType::Ipv4 => {
            let ip = ptr_at::<Ipv4Hdr>(ctx, offset)?;
            if unsafe { (*ip).protocol } != IpProto::Udp { return Ok(xdp_action::XDP_PASS); }
            let addr = unsafe { (*ip).src_addr }.to_be_bytes();
            src_ip[10] = 0xFF; src_ip[11] = 0xFF; // IPv4-mapped IPv6 格式
            src_ip[12..16].copy_from_slice(&addr);
            offset += Ipv4Hdr::LEN;
        }
        EtherType::Ipv6 => {
            let ip = ptr_at::<Ipv6Hdr>(ctx, offset)?;
            if unsafe { (*ip).next_hdr } != IpProto::Udp { return Ok(xdp_action::XDP_PASS); }
            src_ip = unsafe { (*ip).src_addr.in6_u.u6_addr8 };
            offset += Ipv6Hdr::LEN;
        }
        _ => return Ok(xdp_action::XDP_PASS),
    }

    // 2. 配置获取
    let (target_port, flags, current_time) = unsafe {
        let p = ETP_GLOBAL_CONFIG.get(&CONFIG_SETTING_PORT).map(|v| *v as u16).unwrap_or(4433);
        let f = ETP_GLOBAL_CONFIG.get(&CONFIG_SETTING_FLAGS).map(|v| *v).unwrap_or(0);
        let t = ETP_GLOBAL_CONFIG.get(&CONFIG_CURRENT_UNIX_SEC).map(|v| *v as u64).unwrap_or(0);
        (p, f, t)
    };

    // 3. 四层解析
    let udp = ptr_at::<UdpHdr>(ctx, offset)?;
    if u16::from_be(unsafe { (*udp).dest }) != target_port {
        // 如果开启了严苛模式，非目标端口的包直接丢弃
        return if (flags & FLAG_DROP_ALL_OTHERS) != 0 { Ok(xdp_action::XDP_DROP) } else { Ok(xdp_action::XDP_PASS) };
    }
    offset += UdpHdr::LEN;

    // 4. ACL 校验
    if (flags & FLAG_ACL_ENABLED) != 0 {
        if unsafe { ETP_IP_WHITELIST.get(&src_ip).is_none() } {
            return Ok(xdp_action::XDP_DROP); 
        }
    }

    // 5. ETP 令牌深度校验
    // 报文结构: UDP Data -> [Token: 32B][Nonce: 8B]...
    let token_ptr = ptr_at::<[u8; 32]>(ctx, offset)?;
    let token = unsafe { *token_ptr };

    if let Some(expiry) = unsafe { ALLOWED_TOKENS.get(&token) } {
        // 校验有效期 (由用户态定期刷新的 Unix Sec 判定)
        if current_time > *expiry {
            return Ok(xdp_action::XDP_DROP);
        }
        // 验证通过，允许进入用户态内存池
        return Ok(xdp_action::XDP_PASS);
    }

    // 非法连接尝试
    Ok(xdp_action::XDP_DROP)
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + mem::size_of::<T>() > end { return Err(()); }
    Ok((start + offset) as *const T)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }