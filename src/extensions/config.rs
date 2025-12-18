// etp-core/src/extensions/config.rs

use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::path::PathBuf;
use std::thread;
use std::fs;
use std::collections::HashMap;
use std::str::FromStr;

use log::{info, error, warn, debug};
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use anyhow::{Result, anyhow, Context};
use notify::{Watcher, RecursiveMode, Event, EventKind};
use reqwest::blocking::Client;
use url::Url;
use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use regex::Regex;
use std::sync::OnceLock;

// ============================================================================
//  1. 基础定义与结构
// ============================================================================

const MAX_REDIRECT_DEPTH: usize = 5;

/// 配置获取结果
pub enum FetchResult {
    /// 直接获取到了配置数据 (二进制流)
    Data(Vec<u8>),
    /// 获取到了一个新的 URI，需要递归解析 (例如 ENS -> IPFS)
    Redirect(String),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConfigFormat {
    Json,
    Toml,
    Yaml,
    Ini,
    Xml,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignedConfigPayload {
    pub content: String,
    pub format: String,
    pub timestamp: u64,
    pub signature: String,
}

pub struct DynamicConfig {
    configs: Arc<RwLock<Value>>,
    trust_anchor: Option<VerifyingKey>,
}

// ============================================================================
//  2. 协议适配器接口 (Provider Traits)
// ============================================================================

pub trait ConfigProvider: Send + Sync {
    /// 协议 Scheme (e.g. "http", "ipfs")
    fn scheme(&self) -> &'static str;
    /// 获取配置内容
    fn fetch(&self, uri: &str) -> Result<FetchResult>;
}

// --- 具体实现 ---

pub struct HttpProvider {
    pub client: Client,
}
impl ConfigProvider for HttpProvider {
    fn scheme(&self) -> &'static str { "http" } // 主 Scheme
    fn fetch(&self, uri: &str) -> Result<FetchResult> {
        let resp = self.client.get(uri).send()?;
        if !resp.status().is_success() {
            return Err(anyhow!("HTTP Error: {}", resp.status()));
        }
        let bytes = resp.bytes()?;
        if bytes.len() > 10 * 1024 * 1024 { 
            return Err(anyhow!("Config too large (>10MB)"));
        }
        Ok(FetchResult::Data(bytes.to_vec()))
    }
}

pub struct IpfsProvider {
    pub gateway: String,
    pub client: Client,
}
impl ConfigProvider for IpfsProvider {
    fn scheme(&self) -> &'static str { "ipfs" }
    fn fetch(&self, uri: &str) -> Result<FetchResult> {
        let cid = uri.strip_prefix("ipfs://").unwrap_or(uri);
        // 使用配置的网关地址
        let url = format!("{}/ipfs/{}", self.gateway.trim_end_matches('/'), cid);
        debug!("IPFS: Fetching via gateway {}", url);
        
        let resp = self.client.get(&url).send()?;
        if !resp.status().is_success() {
            return Err(anyhow!("IPFS Gateway Error: {}", resp.status()));
        }
        Ok(FetchResult::Data(resp.bytes()?.to_vec()))
    }
}

/// ENS 提供者 (客户端)
/// 依赖外部或本地运行的 ENS Gateway 服务
pub struct EnsProvider {
    pub rpc_url: String,
    pub client: Client,
}
impl ConfigProvider for EnsProvider {
    fn scheme(&self) -> &'static str { "ens" }
    
    fn fetch(&self, uri: &str) -> Result<FetchResult> {
        let domain = uri.strip_prefix("ens://").unwrap_or(uri);
        let resolve_url = format!("{}/resolve?name={}&key=etp-config", self.rpc_url.trim_end_matches('/'), domain);
        
        // 执行请求 (带简单重试)
        let mut attempts = 0;
        loop {
            attempts += 1;
            let resp = self.client.get(&resolve_url).send();
            
            match resp {
                Ok(r) => {
                    if r.status().is_success() {
                        let resolved_uri: String = r.json().context("Failed to parse ENS gateway response")?;
                        info!("ENS Resolved: {} -> {}", domain, resolved_uri);
                        return Ok(FetchResult::Redirect(resolved_uri));
                    } else if r.status().is_server_error() && attempts < 3 {
                        thread::sleep(Duration::from_millis(500 * attempts));
                        continue;
                    } else {
                        let err_msg = r.text().unwrap_or_default();
                        return Err(anyhow!("ENS Resolution Failed ({}): {}", r.status(), err_msg));
                    }
                },
                Err(e) => {
                    if attempts >= 3 { return Err(anyhow!("ENS Gateway Unreachable: {}", e)); }
                    thread::sleep(Duration::from_millis(500 * attempts));
                }
            }
        }
    }
}

pub struct NodeIdProvider {
    pub dht_gateway: String,
    pub client: Client,
}
impl ConfigProvider for NodeIdProvider {
    fn scheme(&self) -> &'static str { "nodeid" }
    fn fetch(&self, uri: &str) -> Result<FetchResult> {
        let key = if uri.starts_with("nodeid://") {
            uri.strip_prefix("nodeid://").unwrap()
        } else {
            uri.strip_prefix("tns://").unwrap()
        };
        
        let url = format!("{}/{}", self.dht_gateway.trim_end_matches('/'), key);
        let resp = self.client.get(&url).send()?;
        if !resp.status().is_success() {
            return Err(anyhow!("DHT Lookup Error: {}", resp.status()));
        }
        Ok(FetchResult::Data(resp.bytes()?.to_vec()))
    }
}

// ============================================================================
//  3. 核心配置管理器
// ============================================================================

pub struct ConfigManager {
    config: Arc<DynamicConfig>,
    // 使用 Arc<dyn> 允许同一实例被多个 Scheme 共享
    providers: HashMap<String, Arc<dyn ConfigProvider>>,
}

impl ConfigManager {
    pub fn new(initial: Value, trust_key_hex: Option<String>) -> Result<Self> {
        let config = Arc::new(DynamicConfig::new(initial, trust_key_hex)?);
        Ok(Self {
            config,
            providers: HashMap::new(),
        })
    }

    /// 注册协议提供者 (生产级完整实现)
    pub fn register_provider<P: ConfigProvider + 'static>(&mut self, provider: P) {
        // 1. 将 Provider 包装进 Arc，以便多处引用
        let provider_arc = Arc::new(provider);
        let main_scheme = provider_arc.scheme();
        
        // 2. 注册主 Scheme
        self.providers.insert(main_scheme.to_string(), provider_arc.clone());
        info!("ConfigManager: Registered provider for '{}'", main_scheme);

        // 3. 处理自动别名 (Auto-Aliasing)
        // 利用 Arc 共享同一个实例，无需 Clone 内部逻辑，高效且一致
        if main_scheme == "http" {
            // HttpProvider 同时支持 https://
            self.providers.insert("https".to_string(), provider_arc.clone());
            debug!("ConfigManager: Auto-registered alias 'https' -> 'http' provider");
        }
        
        // 可以扩展其他别名逻辑，例如:
        // if main_scheme == "ipfs" { self.providers.insert("ipns".to_string(), provider_arc); }
    }

    pub fn register_defaults(&mut self) {
        let client = Client::builder().timeout(Duration::from_secs(30)).build().unwrap();
        
        // 注册 HTTP (会自动处理 HTTPS)
        self.register_provider(HttpProvider { client: client.clone() });

        // 注册 IPFS
        self.register_provider(IpfsProvider { 
            gateway: "https://ipfs.io".to_string(), 
            client: client.clone() 
        });
    }

    /// 从 URI 加载配置 (支持递归解析)
    pub fn load_from_uri(&self, initial_uri: &str) -> Result<()> {
        let mut current_uri = initial_uri.to_string();
        let mut depth = 0;

        loop {
            if depth >= MAX_REDIRECT_DEPTH {
                return Err(anyhow!("Max redirect depth ({}) exceeded at {}", MAX_REDIRECT_DEPTH, current_uri));
            }

            // 1. 解析 Scheme
            let parsed = Url::parse(&current_uri).or_else(|_| Url::parse(&format!("dummy://{}", current_uri)))?;
            let scheme = if current_uri.starts_with("magnet:") { "magnet" } else { parsed.scheme() };

            // 2. 查找 Provider
            let provider = self.providers.get(scheme)
                .ok_or_else(|| anyhow!("No provider registered for scheme: '{}'", scheme))?;

            info!("Config: Fetching from [{}]", current_uri);

            // 3. 执行获取
            match provider.fetch(&current_uri)? {
                FetchResult::Data(bytes) => {
                    // 终点：处理数据
                    return self.process_payload(&bytes);
                },
                FetchResult::Redirect(new_uri) => {
                    // 中继：更新 URI，进入下一次循环
                    debug!("Config: Redirected from {} -> {}", current_uri, new_uri);
                    current_uri = new_uri;
                    depth += 1;
                }
            }
        }
    }

    fn process_payload(&self, bytes: &[u8]) -> Result<()> {
        // 1. Parse Wrapper
        let payload: SignedConfigPayload = serde_json::from_slice(bytes)
            .context("Failed to parse signed config wrapper")?;

        // 2. Verify Security
        if let Some(key) = &self.config.trust_anchor {
            ConfigLoader::verify_payload(&payload, key)?;
        } else {
            warn!("SECURITY WARNING: Loading remote config WITHOUT signature verification!");
        }

        // 3. Parse Content
        let format = ConfigLoader::detect_format(&payload.format);
        let value = ConfigLoader::parse_content(&payload.content, format)?;

        // 4. Update
        self.config.update(value);
        info!("Config successfully updated and hot-reloaded.");
        Ok(())
    }

    pub fn start_polling(self: Arc<Self>, uri: String, interval: Duration) {
        thread::Builder::new().name("cfg-poll".into()).spawn(move || {
            loop {
                thread::sleep(interval);
                if let Err(e) = self.load_from_uri(&uri) {
                    warn!("Config Polling Failed: {}", e);
                }
            }
        }).unwrap();
    }
    
    pub fn get_config(&self) -> Arc<DynamicConfig> {
        self.config.clone()
    }
}

// ============================================================================
//  4. 内部工具类
// ============================================================================

impl DynamicConfig {
    pub fn new(initial: Value, trust_key_hex: Option<String>) -> Result<Self> {
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

    fn resolve_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
        static RE: OnceLock<regex::Regex> = OnceLock::new();
        let re = RE.get_or_init(|| regex::Regex::new(r"^([^\[]+)(?:\[(\d+)\])?$").unwrap());
        
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

pub struct ConfigLoader;

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
                let json_str = serde_json::to_string(&toml_val)?;
                serde_json::from_str(&json_str).context("TOML->JSON conv error")
            },
            ConfigFormat::Ini => {
                let conf = rust_ini::Ini::load_from_str(content).map_err(|e| anyhow!("INI error: {}", e))?;
                let mut root_map = serde_json::Map::new();
                for (sec_opt, props) in conf.iter() {
                    let mut section_json = serde_json::Map::new();
                    for (k, v) in props.iter() {
                        let val = if let Ok(b) = bool::from_str(v) { Value::Bool(b) }
                        else if let Ok(n) = v.parse::<i64>() { json!(n) }
                        else if let Ok(f) = v.parse::<f64>() { json!(f) }
                        else { Value::String(v.to_string()) };
                        section_json.insert(k.to_string(), val);
                    }
                    if let Some(sec) = sec_opt {
                        root_map.insert(sec.to_string(), Value::Object(section_json));
                    } else {
                        for (k, v) in section_json { root_map.insert(k, v); }
                    }
                }
                Ok(Value::Object(root_map))
            },
            ConfigFormat::Xml => serde_xml_rs::from_str(content).context("XML error")
        }
    }

    fn verify_payload(payload: &SignedConfigPayload, key: &VerifyingKey) -> Result<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        if payload.timestamp > now + 300 { return Err(anyhow!("Future timestamp in config")); }
        if now.saturating_sub(payload.timestamp) > 86400 * 30 { return Err(anyhow!("Config payload expired")); }

        let mut data = Vec::new();
        data.extend_from_slice(&payload.timestamp.to_be_bytes());
        data.extend_from_slice(payload.content.as_bytes());
        
        let sig_bytes = hex::decode(&payload.signature)?;
        let sig = Signature::from_slice(&sig_bytes)?;
        
        key.verify(&data, &sig).context("Invalid config signature")?;
        Ok(())
    }
}

pub struct ConfigWatcher;
impl ConfigWatcher {
    pub fn watch_file(manager: Arc<ConfigManager>, path: PathBuf) -> Result<()> {
        thread::Builder::new().name("cfg-file-watch".into()).spawn(move || {
            let (tx, rx) = std::sync::mpsc::channel();
            let mut watcher = notify::recommended_watcher(tx).unwrap();
            let _ = watcher.watch(&path, RecursiveMode::NonRecursive);

            info!("Config: Watching file {:?}", path);

            loop {
                match rx.recv() {
                    Ok(Ok(Event { kind, .. })) => {
                        if matches!(kind, EventKind::Modify(_)) {
                            info!("Config: File modified, reloading...");
                            thread::sleep(Duration::from_millis(500)); // Debounce
                            
                            if let Ok(content) = fs::read_to_string(&path) {
                                let fmt = ConfigLoader::detect_format(path.extension().and_then(|s| s.to_str()).unwrap_or("json"));
                                match ConfigLoader::parse_content(&content, fmt) {
                                    Ok(val) => manager.config.update(val),
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
}