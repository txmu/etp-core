// src/eui/rss/mod.rs

#![cfg(feature = "eui-rss")]

use std::sync::Arc;
use rss::Channel;
use anyhow::{Result, anyhow};
use log::{info, error, debug};
use crate::eui::state::RssItem;

pub struct RssEngine {
    client: reqwest::Client,
}

impl RssEngine {
    pub fn new() -> Self {
        let mut headers = reqwest::header::HeaderMap::new();
        // 生产级伪装：防止 RSSHub 或其他反爬虫机制拦截默认的 reqwest UA
        headers.insert(
            reqwest::header::USER_AGENT,
            reqwest::header::HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) ETP-Core/2.3.5")
        );

        Self {
            client: reqwest::Client::builder()
                .default_headers(headers)
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }

    /// 抓取并解析单个 Feed
    pub async fn fetch_feed(&self, url: &str, source_label: &str) -> Result<Vec<RssItem>> {
        debug!("RSS: Fetching from {} [{}]", url, source_label);
        
        let content = self.client.get(url).send().await?.bytes().await?;
        let channel = Channel::read_from(&content[..])
            .map_err(|e| anyhow!("Parse error for {}: {}", source_label, e))?;

        let items = channel.items().iter().map(|item| {
            RssItem {
                title: item.title().unwrap_or("No Title").to_string(),
                link: item.link().unwrap_or("#").to_string(),
                description: html_escape::decode_html_entities(
                    item.description().unwrap_or("...")
                ).to_string(),
                pub_date: item.pub_date().unwrap_or("Unknown Date").to_string(),
                author: item.author().unwrap_or("Anonymous").to_string(),
                source_name: source_label.to_string(),
                is_read: false,
            }
        }).collect();

        Ok(items)
    }
}