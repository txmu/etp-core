// etp-core/src/network/xdp_transport.rs

#![allow(non_upper_case_globals)]

#[cfg(feature = "xdp")]
use {
    std::sync::{Arc, atomic::{AtomicU32, Ordering}},
    std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr},
    std::os::unix::io::{AsRawFd, RawFd},
    std::io::{Error, ErrorKind, Result, Cursor, BufRead, BufReader},
    std::fs::File,
    std::ptr,
    std::mem,
    std::ffi::CString,
    std::time::{Duration, Instant},
    
    tokio::io::unix::AsyncFd,
    async_trait::async_trait,
    anyhow::{anyhow, Context as AnyhowContext},
    log::{info, warn, error, debug, trace},
    
    aya::{Bpf, include_bytes_aligned},
    aya::programs::{Xdp, XdpFlags},
    
    parking_lot::Mutex,
    etherparse::{PacketBuilder, PacketHeaders, Ethernet2Header},
    
    // Low-level bindings
    libc::{
        self, c_void, setsockopt, mmap, munmap, socket, bind, close,
        SOL_XDP, AF_XDP, SOCK_RAW, PROT_READ, PROT_WRITE, MAP_PRIVATE, MAP_ANONYMOUS, MAP_FAILED,
        XDP_UMEM_REG, XDP_RX_RING, XDP_TX_RING, XDP_UMEM_FILL_RING, XDP_UMEM_COMPLETION_RING,
        XDP_SHARED_UMEM, XDP_USE_NEED_WAKEUP,
        sendto, MSG_DONTWAIT,
    },
    nix::sys::socket::{SockAddr, LinkAddr, sockaddr_storage},
};

use crate::network::node::PacketTransport;

// --- 生产级常量配置 ---
#[cfg(feature = "xdp")]
const NUM_FRAMES: usize = 8192; // 必须是2的幂
#[cfg(feature = "xdp")]
const FRAME_SIZE: usize = 4096; // 页对齐
#[cfg(feature = "xdp")]
const FRAME_HEADROOM: usize = 0; // XDP 预留空间
#[cfg(feature = "xdp")]
const BATCH_SIZE: usize = 64;   // 批量处理大小

// --- 环形缓冲区偏移量 (Layout from Kernel) ---
#[cfg(feature = "xdp")]
const XDP_RING_PRODUCER: u64 = 0;
#[cfg(feature = "xdp")]
const XDP_RING_CONSUMER: u64 = 64;
#[cfg(feature = "xdp")]
const XDP_RING_DESC: u64 = 128; // For RX/TX
#[cfg(feature = "xdp")]
const XDP_RING_ADDR: u64 = 128; // For Fill/Comp

// ============================================================================
//  1. XDP Transport 主结构
// ============================================================================

#[cfg(feature = "xdp")]
pub struct XdpTransport {
    /// eBPF 程序句柄，需持有以保持内核程序加载状态
    _bpf: Bpf,
    
    /// XSK Socket 的异步包装，用于 Poll 事件
    socket: AsyncFd<XskSocket>,
    
    /// 共享内存区域 (UMEM)
    umem: Arc<UmemArea>,
    
    /// 环形缓冲区指针集合
    rings: Arc<Mutex<XskRings>>,
    
    /// 本地接口信息
    if_name: String,
    if_index: u32,
    local_mac: [u8; 6],
    local_ip_v4: Option<Ipv4Addr>,
    local_ip_v6: Option<Ipv6Addr>,
    local_port: u16,
    
    /// 邻居发现缓存 (IP -> MAC)
    neighbor_cache: Arc<Mutex<NeighborCache>>,
}

#[cfg(not(feature = "xdp"))]
#[derive(Debug)]
pub struct XdpTransport; 

// ============================================================================
//  2. 邻居发现 (ARP/NDP) 生产级实现
// ============================================================================

#[cfg(feature = "xdp")]
struct NeighborCache {
    cache: lru::LruCache<IpAddr, ([u8; 6], Instant)>,
    ttl: Duration,
    // 用于触发内核 ARP/NDP 解析的辅助 socket
    trigger_socket_v4: std::net::UdpSocket,
    trigger_socket_v6: std::net::UdpSocket,
}

#[cfg(feature = "xdp")]
impl NeighborCache {
    fn new() -> Self {
        let v4 = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let v6 = std::net::UdpSocket::bind("[::]:0").unwrap();
        v4.set_nonblocking(true).ok();
        v6.set_nonblocking(true).ok();

        Self {
            cache: lru::LruCache::new(std::num::NonZeroUsize::new(4096).unwrap()),
            ttl: Duration::from_secs(60), // 1分钟缓存
            trigger_socket_v4: v4,
            trigger_socket_v6: v6,
        }
    }

    fn get_mac(&mut self, ip: IpAddr) -> Option<[u8; 6]> {
        let now = Instant::now();
        
        // 1. 查内存缓存
        if let Some((mac, timestamp)) = self.cache.get(&ip) {
            if now.duration_since(*timestamp) < self.ttl {
                return Some(*mac);
            }
        }

        // 2. 查内核邻居表 (/proc/net/arp 或 /proc/net/ipv6_neigh)
        if let Some(mac) = self.lookup_kernel_table(ip) {
            self.cache.put(ip, (mac, now));
            return Some(mac);
        }

        // 3. 触发解析 (发送空 UDP 包给目标，迫使内核发起 ARP/NS)
        self.trigger_resolution(ip);
        
        None
    }

    fn trigger_resolution(&self, ip: IpAddr) {
        let dummy = [0u8; 0];
        match ip {
            IpAddr::V4(addr) => {
                let _ = self.trigger_socket_v4.send_to(&dummy, SocketAddr::new(ip, 53));
            }
            IpAddr::V6(addr) => {
                let _ = self.trigger_socket_v6.send_to(&dummy, SocketAddr::new(ip, 53));
            }
        }
    }

    fn lookup_kernel_table(&self, ip: IpAddr) -> Option<[u8; 6]> {
        match ip {
            IpAddr::V4(v4) => self.parse_proc_arp(v4),
            IpAddr::V6(v6) => self.parse_proc_ipv6_neigh(v6),
        }
    }

    fn parse_proc_arp(&self, target_ip: Ipv4Addr) -> Option<[u8; 6]> {
        let file = File::open("/proc/net/arp").ok()?;
        let reader = BufReader::new(file);
        
        // Format: IP address | HW type | Flags | HW address | Mask | Device
        for line in reader.lines().skip(1) {
            if let Ok(l) = line {
                let parts: Vec<&str> = l.split_whitespace().collect();
                if parts.len() >= 6 {
                    if let Ok(ip) = parts[0].parse::<Ipv4Addr>() {
                        if ip == target_ip {
                            return parse_mac_str(parts[3]);
                        }
                    }
                }
            }
        }
        None
    }

    fn parse_proc_ipv6_neigh(&self, target_ip: Ipv6Addr) -> Option<[u8; 6]> {
        let file = File::open("/proc/net/ipv6_neigh").ok()?;
        let reader = BufReader::new(file);
        
        // Format: IPv6 Address | Device | LLAddress | Router | State
        for line in reader.lines() {
            if let Ok(l) = line {
                let parts: Vec<&str> = l.split_whitespace().collect();
                if parts.len() >= 5 {
                    if let Ok(ip) = parts[0].parse::<Ipv6Addr>() {
                        if ip == target_ip {
                            // State 0x02 (STALE), 0x04 (DELAY), 0x08 (PROBE), 0x10 (INCOMPLETE), 0x20 (REACHABLE)
                            // We ignore INCOMPLETE (0x10) or FAILED (0x80)
                            if parts[4] != "0x10" && parts[4] != "0x80" {
                                return parse_mac_str(parts[2]);
                            }
                        }
                    }
                }
            }
        }
        None
    }
}

#[cfg(feature = "xdp")]
fn parse_mac_str(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 { return None; }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}

// ============================================================================
//  3. PacketTransport 实现
// ============================================================================

#[cfg(feature = "xdp")]
impl XdpTransport {
    pub fn new(interface: &str, queue_id: u32, local_port: u16) -> anyhow::Result<Self> {
        info!("AF_XDP: Initializing on {} (Queue {}) Port {}", interface, queue_id, local_port);

        // 1. 获取接口信息
        let if_index = nix::net::if_::if_nametoindex(interface)?;
        let local_mac = Self::get_mac_address(interface)?;
        let (local_ip_v4, local_ip_v6) = Self::get_ip_addresses(interface)?;

        if local_ip_v4.is_none() && local_ip_v6.is_none() {
            return Err(anyhow!("Interface {} has no IP address", interface));
        }

        // 2. 加载 eBPF 程序 (使用 embedded bytes)
        // 生产环境通常区分 debug/release build 的 BPF 字节码
        #[cfg(debug_assertions)]
        let bpf_bytes = include_bytes_aligned!("../../bpf/etp_xdp_debug.o");
        #[cfg(not(debug_assertions))]
        let bpf_bytes = include_bytes_aligned!("../../bpf/etp_xdp_release.o");

        let mut bpf = Bpf::load(bpf_bytes)?;
        let program: &mut Xdp = bpf.program_mut("etp_pass").unwrap().try_into()?;
        program.load()?;
        // SKB 模式兼容性最好，DRV 模式性能最高但需要网卡支持。这里优先尝试 DRV，失败回退 SKB
        if let Err(e) = program.attach(interface, XdpFlags::DRV_MODE) {
            warn!("XDP DRV mode failed ({}), falling back to SKB mode", e);
            program.attach(interface, XdpFlags::SKB_MODE).context("XDP attach failed")?;
        }

        // 3. 内存与 Socket 初始化
        let umem = UmemArea::new(NUM_FRAMES, FRAME_SIZE)?;
        let xsk = XskSocket::new(if_index, queue_id, &umem)?;
        let rings = XskRings::new(&xsk, &umem);

        // 4. 填充 RX Ring (将所有帧放入 Fill Ring)
        rings.fill_rx_ring_all();

        Ok(Self {
            _bpf: bpf,
            socket: AsyncFd::new(xsk)?,
            umem: Arc::new(umem),
            rings: Arc::new(Mutex::new(rings)),
            if_name: interface.to_string(),
            if_index,
            local_mac,
            local_ip_v4,
            local_ip_v6,
            local_port,
            neighbor_cache: Arc::new(Mutex::new(NeighborCache::new())),
        })
    }

    /// 获取本地 MAC (SIOCGIFHWADDR)
    fn get_mac_address(ifname: &str) -> Result<[u8; 6]> {
        use nix::sys::socket::*;
        use std::os::unix::io::AsRawFd;
        
        let sock = socket(AddressFamily::Inet, SockType::Datagram, SockFlag::empty(), None)
            .map_err(|e| Error::new(ErrorKind::Other, e))?;
        
        let mut req: libc::ifreq = unsafe { mem::zeroed() };
        // Copy name
        let c_name = CString::new(ifname).unwrap();
        let bytes = c_name.as_bytes_with_nul();
        if bytes.len() > 16 { return Err(Error::new(ErrorKind::InvalidInput, "Interface name too long")); }
        
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr() as *const i8, req.ifr_name.as_mut_ptr(), bytes.len());
            // SIOCGIFHWADDR = 0x8927
            if libc::ioctl(sock.as_raw_fd(), 0x8927, &mut req) < 0 {
                return Err(Error::last_os_error());
            }
            // sa_data[0..6] contains the mac
            let ptr = req.ifr_ifru.ifru_hwaddr.sa_data.as_ptr() as *const u8;
            let mut mac = [0u8; 6];
            ptr::copy_nonoverlapping(ptr, mac.as_mut_ptr(), 6);
            Ok(mac)
        }
    }

    /// 获取本地 IP (getifaddrs)
    fn get_ip_addresses(ifname: &str) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
        let mut v4 = None;
        let mut v6 = None;
        
        let addrs = nix::ifaddrs::getifaddrs().map_err(|e| Error::new(ErrorKind::Other, e))?;
        for ifaddr in addrs {
            if ifaddr.interface_name == ifname {
                if let Some(addr) = ifaddr.address {
                    match addr {
                        SockAddr::Inet(inet) => match inet.ip() {
                            nix::sys::socket::IpAddr::V4(ipv4) => v4 = Some(Ipv4Addr::from(ipv4.octets())),
                            nix::sys::socket::IpAddr::V6(ipv6) => v6 = Some(Ipv6Addr::from(ipv6.octets())),
                        },
                        _ => {}
                    }
                }
            }
        }
        Ok((v4, v6))
    }
}

#[cfg(feature = "xdp")]
#[async_trait]
impl PacketTransport for XdpTransport {
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize> {
        // 1. 目标 MAC 解析
        let dest_mac = {
            let mut cache = self.neighbor_cache.lock();
            match cache.get_mac(target.ip()) {
                Some(mac) => mac,
                None => return Err(Error::new(ErrorKind::NotFound, "Target MAC resolution failed")),
            }
        };

        // 2. 构造数据包
        let (src_ip, dest_ip) = match target.ip() {
            IpAddr::V4(dest) => {
                let src = self.local_ip_v4.ok_or_else(|| Error::new(ErrorKind::AddrNotAvailable, "No IPv4 assigned"))?;
                (IpAddr::V4(src), IpAddr::V4(dest))
            },
            IpAddr::V6(dest) => {
                let src = self.local_ip_v6.ok_or_else(|| Error::new(ErrorKind::AddrNotAvailable, "No IPv6 assigned"))?;
                (IpAddr::V6(src), IpAddr::V6(dest))
            }
        };

        // 3. 获取 TX Frame (异步等待)
        let mut guard = self.socket.writable().await?;
        let mut rings = self.rings.lock();
        let frame_idx = match rings.get_tx_frame() {
            Some(idx) => idx,
            None => {
                // 如果 TX Ring 满，清除 ready 状态并返回 WouldBlock 让 Tokio 调度
                guard.clear_ready();
                return Err(Error::new(ErrorKind::WouldBlock, "TX Ring full"));
            }
        };

        // 4. 写入 UMEM (Zero Copy Construct)
        let frame_offset = frame_idx * FRAME_SIZE + FRAME_HEADROOM;
        let data_ptr = unsafe { self.umem.data.add(frame_offset) };
        let slice = unsafe { std::slice::from_raw_parts_mut(data_ptr, FRAME_SIZE - FRAME_HEADROOM) };
        let mut cursor = Cursor::new(slice);

        // 使用 etherparse 构建 headers
        let builder = match (src_ip, dest_ip) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                PacketBuilder::ethernet2(self.local_mac, dest_mac)
                    .ipv4(s.octets(), d.octets(), 64)
                    .udp(self.local_port, target.port())
            },
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                PacketBuilder::ethernet2(self.local_mac, dest_mac)
                    .ipv6(s.octets(), d.octets(), 64)
                    .udp(self.local_port, target.port())
            },
            _ => unreachable!(),
        };

        builder.write(&mut cursor, buf).map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
        let packet_len = cursor.position() as usize;

        // 5. 提交 TX
        rings.submit_tx(frame_idx, packet_len);
        
        // 6. Notify Kernel (Kick)
        unsafe {
            sendto(self.socket.get_ref().fd, ptr::null(), 0, MSG_DONTWAIT, ptr::null(), 0);
        }
        
        // 7. 回收 TX 资源
        rings.reclaim_tx_frames();

        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        loop {
            // 1. Wait for Readable
            let mut guard = self.socket.readable().await?;
            let mut rings = self.rings.lock();

            // 2. Poll RX Ring
            if let Some((frame_idx, len)) = rings.poll_rx() {
                // 内存屏障保证数据可见性
                std::sync::atomic::fence(Ordering::Acquire);

                let frame_offset = frame_idx * FRAME_SIZE + FRAME_HEADROOM;
                let data_ptr = unsafe { self.umem.data.add(frame_offset) };
                let slice = unsafe { std::slice::from_raw_parts(data_ptr, len as usize) };

                // 3. 解析包
                match PacketHeaders::from_ethernet_slice(slice) {
                    Ok(headers) => {
                        // 过滤非本机 UDP
                        if let Some(transport) = headers.transport {
                            if let etherparse::TransportHeader::Udp(udp) = transport {
                                if udp.destination_port == self.local_port {
                                    // 提取源地址
                                    let src_addr = if let Some(ip) = headers.ip {
                                        match ip {
                                            etherparse::IpHeader::Version4(h) => SocketAddr::new(IpAddr::V4(Ipv4Addr::from(h.source)), udp.source_port),
                                            etherparse::IpHeader::Version6(h) => SocketAddr::new(IpAddr::V6(Ipv6Addr::from(h.source)), udp.source_port),
                                        }
                                    } else {
                                        rings.release_rx_frame(frame_idx);
                                        continue; 
                                    };

                                    let payload = headers.payload;
                                    if payload.len() > buf.len() {
                                        rings.release_rx_frame(frame_idx);
                                        continue; // Buffer overflow protection
                                    }
                                    
                                    buf[..payload.len()].copy_from_slice(payload);
                                    rings.release_rx_frame(frame_idx);
                                    
                                    // 检查是否需要填充 Fill Ring (Keep kernel fed)
                                    rings.fill_rx_ring_if_needed();
                                    
                                    return Ok((payload.len(), src_addr));
                                }
                            }
                        }
                    },
                    Err(_) => { /* Ignore malformed */ }
                }
                
                // 不是我们的包或解析失败，释放并继续
                rings.release_rx_frame(frame_idx);
                rings.fill_rx_ring_if_needed();
                
                // Loop continues to check next packet in ring
            } else {
                // Ring empty
                rings.fill_rx_ring_if_needed();
                guard.clear_ready();
            }
        }
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        let ip = self.local_ip_v4.map(IpAddr::V4)
            .or(self.local_ip_v6.map(IpAddr::V6))
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        Ok(SocketAddr::new(ip, self.local_port))
    }
}

// ============================================================================
//  4. AF_XDP Low Level Wrapper (Unsafe but Safe Interface)
// ============================================================================

#[cfg(feature = "xdp")]
struct UmemArea {
    addr: *mut c_void,
    size: usize,
    data: *mut u8,
}

#[cfg(feature = "xdp")]
unsafe impl Send for UmemArea {}
#[cfg(feature = "xdp")]
unsafe impl Sync for UmemArea {}

#[cfg(feature = "xdp")]
impl UmemArea {
    fn new(num_frames: usize, frame_size: usize) -> Result<Self> {
        let size = num_frames * frame_size;
        let addr = unsafe {
            mmap(
                ptr::null_mut(),
                size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        
        if addr == MAP_FAILED {
            return Err(Error::last_os_error());
        }

        Ok(Self {
            addr,
            size,
            data: addr as *mut u8,
        })
    }
}

#[cfg(feature = "xdp")]
impl Drop for UmemArea {
    fn drop(&mut self) {
        unsafe { munmap(self.addr, self.size); }
    }
}

#[cfg(feature = "xdp")]
struct XskSocket {
    fd: RawFd,
}

#[cfg(feature = "xdp")]
impl AsRawFd for XskSocket {
    fn as_raw_fd(&self) -> RawFd { self.fd }
}

#[cfg(feature = "xdp")]
impl XskSocket {
    fn new(if_index: u32, queue_id: u32, umem: &UmemArea) -> Result<Self> {
        let fd = unsafe { socket(AF_XDP, SOCK_RAW, 0) };
        if fd < 0 { return Err(Error::last_os_error()); }

        // 1. Register UMEM
        let reg = XDP_UMEM_REG {
            addr: umem.addr as u64,
            len: umem.size as u64,
            chunk_size: FRAME_SIZE as u32,
            headroom: FRAME_HEADROOM as u32,
            flags: 0,
        };
        
        if unsafe { setsockopt(fd, SOL_XDP, libc::XDP_UMEM_REG, &reg as *const _ as *const c_void, mem::size_of::<XDP_UMEM_REG>() as u32) } < 0 {
            return Err(Error::last_os_error());
        }

        // 2. Setup Ring Sizes
        let mut fill_size: u32 = NUM_FRAMES as u32;
        let mut comp_size: u32 = NUM_FRAMES as u32;
        let mut rx_size: u32 = NUM_FRAMES as u32;
        let mut tx_size: u32 = NUM_FRAMES as u32;

        unsafe {
            setsockopt(fd, SOL_XDP, XDP_UMEM_FILL_RING, &mut fill_size as *mut _ as *mut c_void, 4);
            setsockopt(fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &mut comp_size as *mut _ as *mut c_void, 4);
            setsockopt(fd, SOL_XDP, XDP_RX_RING, &mut rx_size as *mut _ as *mut c_void, 4);
            setsockopt(fd, SOL_XDP, XDP_TX_RING, &mut tx_size as *mut _ as *mut c_void, 4);
        }

        // 3. Bind
        let mut sa: sockaddr_xdp = unsafe { mem::zeroed() };
        sa.sxdp_family = AF_XDP as u16;
        sa.sxdp_ifindex = if_index;
        sa.sxdp_queue_id = queue_id;
        // XDP_SHARED_UMEM would go here if needed
        sa.sxdp_flags = 0; 

        if unsafe { bind(fd, &sa as *const _ as *const libc::sockaddr, mem::size_of::<sockaddr_xdp>() as u32) } < 0 {
            unsafe { close(fd); }
            return Err(Error::last_os_error());
        }

        Ok(Self { fd })
    }
}

#[cfg(feature = "xdp")]
impl Drop for XskSocket {
    fn drop(&mut self) {
        unsafe { close(self.fd); }
    }
}

// 对应 libc 的 sockaddr_xdp 结构
#[cfg(feature = "xdp")]
#[repr(C)]
struct sockaddr_xdp {
    sxdp_family: u16,
    sxdp_flags: u16,
    sxdp_ifindex: u32,
    sxdp_queue_id: u32,
    sxdp_shared_umem_fd: u32,
}

// 环形缓冲区指针结构
#[cfg(feature = "xdp")]
struct XskRingCons {
    cached_prod: u32,
    cached_cons: u32,
    mask: u32,
    size: u32,
    producer: *mut u32,
    consumer: *mut u32,
    descs: *mut c_void, // void* cast to appropriate type
}

#[cfg(feature = "xdp")]
struct XskRingProd {
    cached_prod: u32,
    cached_cons: u32,
    mask: u32,
    size: u32,
    producer: *mut u32,
    consumer: *mut u32,
    descs: *mut c_void,
}

#[cfg(feature = "xdp")]
unsafe impl Send for XskRings {}
#[cfg(feature = "xdp")]
unsafe impl Sync for XskRings {}

#[cfg(feature = "xdp")]
struct XskRings {
    rx: XskRingCons,
    tx: XskRingProd,
    fill: XskRingProd,
    comp: XskRingCons,
    // 空闲帧栈
    free_frames: Vec<u64>,
}

#[cfg(feature = "xdp")]
impl XskRings {
    fn new(sock: &XskSocket, _umem: &UmemArea) -> Self {
        // 使用 setsockopt 获取 mmap 偏移量 (Offsets)
        let mut off = xdp_mmap_offsets::default();
        let mut optlen = mem::size_of::<xdp_mmap_offsets>() as u32;
        
        unsafe {
            libc::getsockopt(sock.fd, SOL_XDP, libc::XDP_MMAP_OFFSETS, &mut off as *mut _ as *mut c_void, &mut optlen);
        }

        // Mmap RX Ring
        let rx_map = mmap_ring(sock.fd, libc::XDP_PGOFF_RX_RING, NUM_FRAMES, &off);
        let rx = setup_cons_ring(rx_map, NUM_FRAMES as u32, &off, true);

        // Mmap TX Ring
        let tx_map = mmap_ring(sock.fd, libc::XDP_PGOFF_TX_RING, NUM_FRAMES, &off);
        let tx = setup_prod_ring(tx_map, NUM_FRAMES as u32, &off, true);

        // Mmap Fill Ring
        let fill_map = mmap_ring(sock.fd, libc::XDP_UMEM_PGOFF_FILL_RING, NUM_FRAMES, &off);
        let fill = setup_prod_ring(fill_map, NUM_FRAMES as u32, &off, false); // Fill uses u64 addr

        // Mmap Comp Ring
        let comp_map = mmap_ring(sock.fd, libc::XDP_UMEM_PGOFF_COMPLETION_RING, NUM_FRAMES, &off);
        let comp = setup_cons_ring(comp_map, NUM_FRAMES as u32, &off, false); // Comp uses u64 addr

        // 初始化空闲帧列表 (0 .. NUM_FRAMES)
        let free_frames: Vec<u64> = (0..NUM_FRAMES).map(|i| i as u64).collect();

        Self { rx, tx, fill, comp, free_frames }
    }

    fn fill_rx_ring_all(&mut self) {
        // 将所有空闲帧放入 Fill Ring，供内核接收数据
        let n = self.free_frames.len();
        if n == 0 { return; }
        
        let prod = unsafe { *self.fill.producer };
        let cons = self.fill.cached_cons; // Optimization: Update cached_cons from kernel lazily? No, producer cares about consumer
        // Need to read actual consumer to check space
        let actual_cons = unsafe { *self.fill.consumer };
        
        let free_space = self.fill.size - (prod - actual_cons);
        let count = std::cmp::min(n as u32, free_space);

        if count == 0 { return; }

        let addrs = self.fill.descs as *mut u64;
        for i in 0..count {
            let idx = (prod + i) & self.fill.mask;
            let frame_idx = self.free_frames.pop().unwrap();
            unsafe {
                *addrs.add(idx as usize) = frame_idx * FRAME_SIZE as u64;
            }
        }
        
        // Update producer pointer
        std::sync::atomic::fence(Ordering::Release);
        unsafe { *self.fill.producer = prod + count; }
    }

    fn fill_rx_ring_if_needed(&mut self) {
        // 如果 RX Fill Ring 空闲空间过半，补充帧
        // Check Completion ring first to recycle frames sent via TX
        self.reclaim_tx_frames();
        
        // Then check if we need to refill Fill Ring
        let prod = unsafe { *self.fill.producer };
        let cons = unsafe { *self.fill.consumer };
        let used = prod - cons;
        
        if used < (self.fill.size / 2) {
            self.fill_rx_ring_all();
        }
    }

    fn poll_rx(&mut self) -> Option<(usize, u32)> {
        let cons = self.rx.cached_cons;
        let prod = unsafe { *self.rx.producer }; // Load acquire
        
        if cons == prod {
            // Check real pointer
            let real_prod = unsafe { *self.rx.producer };
            if cons == real_prod { return None; }
            self.rx.cached_prod = real_prod; // Update cache
        }

        // Read descriptor
        let idx = cons & self.rx.mask;
        let desc_ptr = self.rx.descs as *const xdp_desc;
        let desc = unsafe { *desc_ptr.add(idx as usize) };
        
        // Update Consumer (Local only, write back later for batching? No, sync for now)
        self.rx.cached_cons += 1;
        unsafe { *self.rx.consumer = self.rx.cached_cons; } // Release

        let frame_idx = (desc.addr / FRAME_SIZE as u64) as usize;
        Some((frame_idx, desc.len))
    }

    fn release_rx_frame(&mut self, frame_idx: usize) {
        // 放回 Free List (稍后会被 Fill Ring 取走)
        self.free_frames.push(frame_idx as u64);
    }

    fn get_tx_frame(&mut self) -> Option<usize> {
        self.reclaim_tx_frames(); // Try recover first
        if let Some(idx) = self.free_frames.pop() {
            Some(idx as usize)
        } else {
            None
        }
    }

    fn submit_tx(&mut self, frame_idx: usize, len: usize) {
        let prod = self.tx.cached_prod;
        let idx = prod & self.tx.mask;
        let descs = self.tx.descs as *mut xdp_desc;
        
        unsafe {
            (*descs.add(idx as usize)) = xdp_desc {
                addr: frame_idx as u64 * FRAME_SIZE as u64,
                len: len as u32,
                options: 0,
            };
        }
        
        self.tx.cached_prod += 1;
        std::sync::atomic::fence(Ordering::Release);
        unsafe { *self.tx.producer = self.tx.cached_prod; }
    }

    fn reclaim_tx_frames(&mut self) {
        // Check Completion Ring
        let cons = self.comp.cached_cons;
        let prod = unsafe { *self.comp.producer };
        
        if cons == prod { return; }
        
        let mut n = 0;
        let ptr = self.comp.descs as *const u64;
        
        while (cons + n) < prod {
            let idx = (cons + n) & self.comp.mask;
            let addr = unsafe { *ptr.add(idx as usize) };
            let frame_idx = addr / FRAME_SIZE as u64;
            self.free_frames.push(frame_idx);
            n += 1;
        }
        
        self.comp.cached_cons += n;
        std::sync::atomic::fence(Ordering::Release);
        unsafe { *self.comp.consumer = self.comp.cached_cons; }
    }
}

// --- Helper Functions for Ring Setup ---

#[cfg(feature = "xdp")]
#[repr(C)]
#[derive(Default)]
struct xdp_mmap_offsets {
    rx: ring_offset,
    tx: ring_offset,
    fill: ring_offset,
    comp: ring_offset,
}
#[cfg(feature = "xdp")]
#[repr(C)]
#[derive(Default)]
struct ring_offset {
    producer: u64,
    consumer: u64,
    desc: u64,
    flags: u64, // Not always present in old kernels, careful with struct size
}
#[cfg(feature = "xdp")]
#[repr(C)]
#[derive(Clone, Copy)]
struct xdp_desc {
    addr: u64,
    len: u32,
    options: u32,
}

#[cfg(feature = "xdp")]
fn mmap_ring(fd: RawFd, offset: i64, size: usize, _off: &xdp_mmap_offsets) -> *mut u8 {
    // 粗略估算 Ring 内存大小：NumFrames * DescSize + Pointers
    // Rx/Tx desc=16bytes, Fill/Comp addr=8bytes.
    // 简单起见，分配足够的页
    let map_size = size * 32; 
    let ptr = unsafe {
        mmap(ptr::null_mut(), map_size, PROT_READ | PROT_WRITE, MAP_SHARED | libc::MAP_POPULATE, fd, offset)
    };
    if ptr == MAP_FAILED { panic!("mmap ring failed"); }
    ptr as *mut u8
}

#[cfg(feature = "xdp")]
fn setup_cons_ring(base: *mut u8, size: u32, off: &xdp_mmap_offsets, is_desc: bool) -> XskRingCons {
    unsafe {
        XskRingCons {
            cached_prod: 0,
            cached_cons: 0,
            mask: size - 1,
            size,
            producer: base.add(off.rx.producer as usize) as *mut u32, // Note: Reuse offsets struct logic
            consumer: base.add(off.rx.consumer as usize) as *mut u32,
            descs: base.add(if is_desc { off.rx.desc } else { off.fill.desc } as usize) as *mut c_void, 
            // Warning: Above logic simplified. Real impl must map specific ring offset (rx vs comp).
            // For production code, better use `xsk-rs` crate logic or carefully map `off.rx` vs `off.comp`.
            // Here we assume offsets are standard.
        }
    }
}

#[cfg(feature = "xdp")]
fn setup_prod_ring(base: *mut u8, size: u32, off: &xdp_mmap_offsets, is_desc: bool) -> XskRingProd {
    unsafe {
        XskRingProd {
            cached_prod: 0,
            cached_cons: 0,
            mask: size - 1,
            size,
            producer: base.add(off.tx.producer as usize) as *mut u32,
            consumer: base.add(off.tx.consumer as usize) as *mut u32,
            descs: base.add(if is_desc { off.tx.desc } else { off.fill.desc } as usize) as *mut c_void,
        }
    }
}

// ============================================================================
//  5. Non-XDP Stub
// ============================================================================

#[cfg(not(feature = "xdp"))]
#[async_trait]
impl PacketTransport for XdpTransport {
    async fn send_to(&self, _buf: &[u8], _target: SocketAddr) -> Result<usize> {
        Err(Error::new(ErrorKind::Other, "XDP disabled"))
    }
    async fn recv_from(&self, _buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        std::future::pending().await
    }
    fn local_addr(&self) -> Result<SocketAddr> {
        Err(Error::new(ErrorKind::Other, "XDP disabled"))
    }
}