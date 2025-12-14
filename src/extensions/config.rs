// etp-core/src/extensions/config.rs

use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::path::PathBuf;
use std::thread;
use std::fs;
use std::collections::HashMap;
use std::str::FromStr;

use log::{info, error, warn, debug, trace};
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use anyhow::{Result, anyhow, Context};
use notify::{Watcher, RecursiveMode, RecommendedWatcher, Event, EventKind}; // Notify v6+ syntax
use reqwest::blocking::Client;
use url::Url;
use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use regex::Regex;

// ============================================================================
//  1. 基础定义与结构
// ============================================================================

/// 配置格式枚举
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConfigFormat {
    Json,
    Toml,
    Yaml,
    Ini,
    Xml,
}

/// 签名配置载荷 (安全传输标准)
#[derive(Serialize, Deserialize, Debug)]
pub struct SignedConfigPayload {
    /// 实际内容 (UTF-8 字符串)
    pub content: String,
    /// 格式提示
    pub format: String,
    /// Unix 时间戳 (秒)
    pub timestamp: u64,
    /// Ed25519 签名 (Hex)
    pub signature: String,
}

/// 动态配置容器
pub struct DynamicConfig {
    configs: Arc<RwLock<Value>>,
    trust_anchor: Option<VerifyingKey>,
}

// ============================================================================
//  2. 协议适配器接口 (Provider Traits)
// ============================================================================

/// 外部配置提供者接口
/// 开发者可以实现此接口来支持新的协议 (如自定义的区块链读取器)
pub trait ConfigProvider: Send + Sync {
    /// 协议 Scheme (e.g., "ipfs", "ens")
    fn scheme(&self) -> &'static str;
    
    /// 获取配置内容 (返回 SignedConfigPayload 的 JSON 序列化字节)
    fn fetch(&self, uri: &str) -> Result<Vec<u8>>;
}

// --- 具体实现 ---

/// HTTP/HTTPS 提供者
struct HttpProvider {
    client: Client,
}
impl ConfigProvider for HttpProvider {
    fn scheme(&self) -> &'static str { "http" } // covers https via implementation
    fn fetch(&self, uri: &str) -> Result<Vec<u8>> {
        let resp = self.client.get(uri).send()?;
        if !resp.status().is_success() {
            return Err(anyhow!("HTTP Error: {}", resp.status()));
        }
        let bytes = resp.bytes()?;
        if bytes.len() > 5 * 1024 * 1024 { // 5MB Limit
            return Err(anyhow!("Config too large"));
        }
        Ok(bytes.to_vec())
    }
}

/// IPFS 提供者 (通过公共网关)
struct IpfsProvider {
    gateway: String,
    client: Client,
}
impl ConfigProvider for IpfsProvider {
    fn scheme(&self) -> &'static str { "ipfs" }
    fn fetch(&self, uri: &str) -> Result<Vec<u8>> {
        // uri: ipfs://<CID>
        let cid = uri.strip_prefix("ipfs://").unwrap_or(uri);
        let url = format!("{}/ipfs/{}", self.gateway, cid);
        debug!("IPFS: Fetching via gateway {}", url);
        
        let resp = self.client.get(&url).send()?;
        if !resp.status().is_success() {
            return Err(anyhow!("IPFS Gateway Error: {}", resp.status()));
        }
        Ok(resp.bytes()?.to_vec())
    }
}

/// ENS 提供者 (通过 Eth RPC 解析 Text Record)
/// 假设 ENS 域名设置了一个 "etp-config" 的 text record，内容是 http/ipfs 链接
struct EnsProvider {
    rpc_url: String,
    client: Client,
}
impl ConfigProvider for EnsProvider {
    fn scheme(&self) -> &'static str { "ens" }
    fn fetch(&self, uri: &str) -> Result<Vec<u8>> {
        // 简化实现：生产环境应使用 ethers-rs 等库解析 ENS
        // 这里模拟：假设有一个 HTTP 服务将 ENS 映射为配置地址
        // uri: ens://alice.eth
        let domain = uri.strip_prefix("ens://").unwrap_or(uri);
        
        // 模拟 RPC 调用 (实际上这里应该是一个真正的 ENS 解析逻辑)
        // 为了演示，我们假设 RPC 返回了重定向地址
        let resolve_url = format!("{}/resolve?name={}&key=etp-config", self.rpc_url, domain);
        let resp = self.client.get(&resolve_url).send()?;
        
        // 假设 RPC 返回的是最终配置的 URL (Redirect)
        let config_url: String = resp.json()?; 
        
        // 递归获取 (这里简单起见，直接用 HttpProvider 逻辑再请求一次)
        let sub_resp = self.client.get(&config_url).send()?;
        Ok(sub_resp.bytes()?.to_vec())
    }
}

/// NodeID/TNS 提供者 (通过 DHT 网关)
struct NodeIdProvider {
    dht_gateway: String, // e.g. "http://127.0.0.1:API_PORT/dht/get"
    client: Client,
}
impl ConfigProvider for NodeIdProvider {
    fn scheme(&self) -> &'static str { "nodeid" } // also covers tns://
    fn fetch(&self, uri: &str) -> Result<Vec<u8>> {
        // uri: nodeid://<HEX_ID> or tns://<NAME>
        let key = if uri.starts_with("nodeid://") {
            uri.strip_prefix("nodeid://").unwrap()
        } else {
            uri.strip_prefix("tns://").unwrap()
        };
        
        let url = format!("{}/{}", self.dht_gateway, key);
        let resp = self.client.get(&url).send()?;
        Ok(resp.bytes()?.to_vec())
    }
}

/// P2P 文件提供者 (BT/Resilio)
/// 依赖本地 API 代理
struct LocalP2pProvider {
    api_endpoint: String, // e.g. "http://127.0.0.1:8888/download"
    client: Client,
}
impl ConfigProvider for LocalP2pProvider {
    fn scheme(&self) -> &'static str { "p2p" } // generic catch-all for magnet/resilio
    fn fetch(&self, uri: &str) -> Result<Vec<u8>> {
        // uri: magnet:?... or resilio://...
        // 发送给本地 Sidecar 服务去下载
        let resp = self.client.post(&self.api_endpoint)
            .body(uri.to_string())
            .send()?;
        
        if resp.status().as_u16() == 202 {
            return Err(anyhow!("P2P download started, please retry later"));
        }
        Ok(resp.bytes()?.to_vec())
    }
}

// ============================================================================
//  3. 核心配置管理器
// ============================================================================

pub struct ConfigManager {
    config: Arc<DynamicConfig>,
    providers: HashMap<String, Box<dyn ConfigProvider>>,
}

impl ConfigManager {
    pub fn new(initial: Value, trust_key_hex: Option<String>) -> Result<Self> {
        let config = Arc::new(DynamicConfig::new(initial, trust_key_hex, None)?);
        Ok(Self {
            config,
            providers: HashMap::new(),
        })
    }

    /// 注册协议提供者
    pub fn register_provider<P: ConfigProvider + 'static>(&mut self, provider: P) {
        self.providers.insert(provider.scheme().to_string(), Box::new(provider));
    }

    /// 注册默认的一组提供者 (Production Defaults)
    pub fn register_defaults(&mut self) {
        let client = Client::builder().timeout(Duration::from_secs(30)).build().unwrap();
        
        // HTTP/HTTPS
        self.register_provider(HttpProvider { client: client.clone() });
        self.providers.insert("https".to_string(), Box::new(HttpProvider { client: client.clone() }));

        // IPFS (Using public gateway)
        self.register_provider(IpfsProvider { 
            gateway: "https://ipfs.io".to_string(), 
            client: client.clone() 
        });

        // TNS/NodeID (Assuming local DHT proxy)
        let dht_prov = NodeIdProvider {
            dht_gateway: "http://127.0.0.1:8080/v1/kv".to_string(),
            client: client.clone()
        };
        self.providers.insert("nodeid".to_string(), Box::new(dht_prov));
        
        // ENS (Mock RPC)
        self.register_provider(EnsProvider {
            rpc_url: "https://mainnet.infura.io/v3/YOUR_KEY".to_string(),
            client: client.clone()
        });
        
        // Magnet/Resilio
        let p2p = LocalP2pProvider {
            api_endpoint: "http://127.0.0.1:9090/p2p/fetch".to_string(),
            client: client.clone()
        };
        self.providers.insert("magnet".to_string(), Box::new(p2p)); // Treat magnet as scheme
        // Resilio usually involves local folder sync, here we treat it as URI fetch via API
        // self.providers.insert("resilio".to_string(), Box::new(p2p_clone)); 
    }

    /// 从 URI 加载配置
    pub fn load_from_uri(&self, uri: &str) -> Result<()> {
        // 1. 识别协议
        let parsed = Url::parse(uri).or_else(|_| Url::parse(&format!("dummy://{}", uri)))?; // Handle generic URIs
        let scheme = if uri.starts_with("magnet:") { "magnet" } else { parsed.scheme() };

        // 2. 查找 Provider
        let provider = self.providers.get(scheme)
            .or_else(|| self.providers.get("nodeid").filter(|_| scheme == "tns")) // Fallback tns -> nodeid
            .ok_or_else(|| anyhow!("No provider for scheme: {}", scheme))?;

        info!("Config: Fetching from {} using {} provider", uri, scheme);

        // 3. Fetch
        let bytes = provider.fetch(uri)?;

        // 4. Parse Wrapper
        let payload: SignedConfigPayload = serde_json::from_slice(&bytes)
            .context("Failed to parse signed wrapper")?;

        // 5. Verify Security
        if let Some(key) = &self.config.trust_anchor {
            ConfigLoader::verify_payload(&payload, key)?;
        } else {
            warn!("SECURITY WARNING: Loading remote config without trust anchor verification!");
        }

        // 6. Parse Content
        let format = ConfigLoader::detect_format(&payload.format);
        let value = ConfigLoader::parse_content(&payload.content, format)?;

        // 7. Update
        self.config.update(value);
        info!("Config successfully updated from {}", uri);
        Ok(())
    }

    /// 启动本地文件监听
    pub fn watch_file(&self, path: PathBuf) -> Result<()> {
        let config_ref = self.config.clone();
        
        thread::Builder::new().name("cfg-file-watch".into()).spawn(move || {
            let (tx, rx) = std::sync::mpsc::channel();
            // Notify v6+ implementation
            let mut watcher = notify::recommended_watcher(tx).unwrap();
            let _ = watcher.watch(&path, RecursiveMode::NonRecursive);

            info!("Config: Watching file {:?}", path);

            loop {
                match rx.recv() {
                    Ok(Ok(Event { kind, .. })) => {
                        if matches!(kind, EventKind::Modify(_)) {
                            info!("Config: File modified, reloading...");
                            // Debounce logic is complex, simple sleep here
                            thread::sleep(Duration::from_millis(500));
                            
                            if let Ok(content) = fs::read_to_string(&path) {
                                let fmt = ConfigLoader::detect_format(path.extension().and_then(|s| s.to_str()).unwrap_or("json"));
                                match ConfigLoader::parse_content(&content, fmt) {
                                    Ok(val) => config_ref.update(val),
                                    Err(e) => error!("Config parse error: {}", e),
                                }
                            }
                        }
                    },
                    Ok(Err(e)) => error!("Watch error: {}", e),
                    Err(_) => break,
                }
            }
        })?;
        Ok(())
    }

    /// 启动网络轮询
    pub fn start_polling(self: Arc<Self>, uri: String, interval: Duration) {
        thread::spawn(move || {
            loop {
                if let Err(e) = self.load_from_uri(&uri) {
                    warn!("Config Polling Failed: {}", e);
                }
                thread::sleep(interval);
            }
        });
    }
    
    pub fn get_config(&self) -> Arc<DynamicConfig> {
        self.config.clone()
    }
}

// ============================================================================
//  4. 内部工具类
// ============================================================================

impl DynamicConfig {
    pub fn new(initial: Value, trust_key_hex: Option<String>, tns_gateway: Option<String>) -> Result<Self> {
        let trust_anchor = if let Some(hex_key) = trust_key_hex {
            let bytes = hex::decode(hex_key).context("Invalid trust key hex")?;
            let key = VerifyingKey::from_bytes(&bytes.try_into().map_err(|_| anyhow!("Bad key len"))?)
                .map_err(|_| anyhow!("Invalid VerifyingKey"))?;
            Some(key)
        } else {
            None
        };
        Ok(Self {
            configs: Arc::new(RwLock::new(initial)),
            trust_anchor,
        })
    }

    pub fn get<T: DeserializeOwned>(&self, path: &str) -> Option<T> {
        let guard = self.configs.read().unwrap();
        Self::resolve_path(&guard, path).and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    pub fn update(&self, new_val: Value) {
        let mut guard = self.configs.write().unwrap();
        *guard = new_val;
    }

    // Robust JSON Path Resolver
    fn resolve_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
        if path.is_empty() { return Some(root); }
        let mut current = root;
        // Regex to match "key" or "key[index]"
        let re = Regex::new(r"^([^\[]+)(?:\[(\d+)\])?$").ok()?;
        
        for part in path.split('.') {
            if let Some(caps) = re.captures(part) {
                let key = caps.get(1)?.as_str();
                current = current.get(key)?;
                
                if let Some(idx_match) = caps.get(2) {
                    let idx: usize = idx_match.as_str().parse().ok()?;
                    current = current.get(idx)?;
                }
            } else {
                return None;
            }
        }
        Some(current)
    }
}

struct ConfigLoader;

impl ConfigLoader {
    fn detect_format(s: &str) -> ConfigFormat {
        match s.to_lowercase().as_str() {
            "toml" => ConfigFormat::Toml,
            "yaml" | "yml" => ConfigFormat::Yaml,
            "ini" => ConfigFormat::Ini,
            "xml" => ConfigFormat::Xml,
            _ => ConfigFormat::Json,
        }
    }

    fn parse_content(content: &str, format: ConfigFormat) -> Result<Value> {
        match format {
            ConfigFormat::Json => serde_json::from_str(content).context("JSON error"),
            ConfigFormat::Yaml => serde_yaml::from_str(content).context("YAML error"),
            ConfigFormat::Toml => {
                let toml_val: toml::Value = toml::from_str(content).context("TOML error")?;
                // Manual conversion needed if types mismatch, but serde_json::to_value usually works for simple structs
                // Here we rely on explicit deserialization if needed, but returning Value is tricky directly from toml crate types.
                // Hack: serialize toml to json string then parse back. Robust but slow.
                let json_str = serde_json::to_string(&toml_val)?;
                serde_json::from_str(&json_str).context("TOML->JSON conv error")
            },
            ConfigFormat::Ini => {
                // Concrete Implementation: INI -> Hierarchical JSON
                let conf = rust_ini::Ini::load_from_str(content).map_err(|e| anyhow!("INI error: {}", e))?;
                let mut root_map = serde_json::Map::new();
                
                for (sec_opt, props) in conf.iter() {
                    let mut section_json = serde_json::Map::new();
                    for (k, v) in props.iter() {
                        // Try to infer types: bool, number, else string
                        let val = if let Ok(b) = bool::from_str(v) { Value::Bool(b) }
                        else if let Ok(n) = v.parse::<i64>() { json!(n) }
                        else if let Ok(f) = v.parse::<f64>() { json!(f) }
                        else { Value::String(v.to_string()) };
                        section_json.insert(k.to_string(), val);
                    }
                    
                    if let Some(sec) = sec_opt {
                        // Nested sections: "network.peers" -> network: { peers: {} }
                        // For simplicity, flat section key
                        root_map.insert(sec.to_string(), Value::Object(section_json));
                    } else {
                        // General properties at root
                        for (k, v) in section_json {
                            root_map.insert(k, v);
                        }
                    }
                }
                Ok(Value::Object(root_map))
            },
            ConfigFormat::Xml => {
                serde_xml_rs::from_str(content).context("XML error")
            }
        }
    }

    fn verify_payload(payload: &SignedConfigPayload, key: &VerifyingKey) -> Result<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        // Allow 5 min skew, expire after 30 days
        if payload.timestamp > now + 300 { return Err(anyhow!("Future timestamp")); }
        if now.saturating_sub(payload.timestamp) > 86400 * 30 { return Err(anyhow!("Config expired")); }

        let mut data = Vec::new();
        data.extend_from_slice(&payload.timestamp.to_be_bytes());
        data.extend_from_slice(payload.content.as_bytes());
        
        let sig_bytes = hex::decode(&payload.signature)?;
        let sig = Signature::from_slice(&sig_bytes)?;
        
        key.verify(&data, &sig).context("Bad signature")?;
        Ok(())
    }
}