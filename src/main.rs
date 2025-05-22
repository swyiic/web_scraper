use std::collections::HashSet;
use std::env;
use std::fs::{self, File};
use std::io::{Write};
use std::path::Path;

use colored::*;
use csv::Writer;
use indicatif::{ProgressBar, ProgressStyle};
use regex::Regex;
use reqwest::blocking::ClientBuilder;
use scraper::{Html, Selector};
use std::time::Duration;
use tempdir::TempDir;
use url::Url;
use urlencoding;

// 配置模块
mod config {
    use std::fs::File;
    use std::io::{Read, Write};
    use colored::Colorize;

    pub struct Config {
        pub blacklist: Vec<String>,
        pub api_core: String,
        pub noise_strings: Vec<String>,
    }

    impl Config {
        pub fn load() -> Self {
            let blacklist = load_blacklist("blacklist.txt");
            let api_core = load_api_core("api_core.txt");
            let noise_strings = load_noise_strings("noise_strings.txt");

            Config {
                blacklist,
                api_core,
                noise_strings,
            }
        }
    }

    fn load_blacklist(file_path: &str) -> Vec<String> {
        let mut blacklist = Vec::new();
        if let Ok(mut file) = File::open(file_path) {
            let mut content = String::new();
            if file.read_to_string(&mut content).is_ok() {
                blacklist = content
                    .lines()
                    .map(|line| line.trim().to_string())
                    .filter(|line| !line.is_empty())
                    .collect();
            } else {
                println!("{} {}", "[*]无法加载黑名单文件:".red(), file_path.red());
            }
        } else {
            println!("{} {}", "[*]无法打开黑名单文件:".red(), file_path.red());
            // 创建默认黑名单文件
            let _ = File::create(file_path);
        }
        blacklist
    }

    fn load_api_core(file_path: &str) -> String {
        let mut api_core = "/api/".to_string();
        if let Ok(mut file) = File::open(file_path) {
            let mut content = String::new();
            if file.read_to_string(&mut content).is_ok() {
                api_core = content.trim().to_string();
                if api_core.is_empty() {
                    api_core = "/api/".to_string();
                }
            } else {
                println!("{} {}", "[*]无法加载api_core文件:".red(), file_path.red());
            }
        } else {
            println!("{} {}", "[*]无法打开api_core文件:".red(), file_path.red());
            // 创建默认api_core文件
            if let Ok(mut file) = File::create(file_path) {
                let _ = file.write_all(api_core.as_bytes());
            }
        }
        api_core
    }

    fn load_noise_strings(file_path: &str) -> Vec<String> {
        let mut noise_strings = Vec::new();
        if let Ok(mut file) = File::open(file_path) {
            let mut content = String::new();
            if file.read_to_string(&mut content).is_ok() {
                noise_strings = content
                    .lines()
                    .map(|line| line.trim().to_string())
                    .filter(|line| !line.is_empty())
                    .collect();
            } else {
                println!("{} {}", "[*]无法加载noise_strings文件:".red(), file_path.red());
            }
        } else {
            println!("{} {}", "[*]无法打开noise_strings文件:".red(), file_path.red());
            let default_noise = vec![
                "/>",
                "><",
                ">;",
                "};",
                "function",
                "button",
                "webpack",
                "chunk",
                "module",
                "export",
                "import",
                "return",
                "var",
                "const",
                "let",
                "/a",
                "/b",
                "javascript",
                ")||['//'+",
                "+",
                "=",
                "/t",
                "xlink",
                "/!",
            ];
            if let Ok(mut file) = File::create(file_path) {
                let _ = file.write_all(default_noise.join("\n").as_bytes());
                noise_strings = default_noise.iter().map(|s| s.to_string()).collect();
            }
        }
        noise_strings
    }
}

const HTML_EXTENSIONS: &[&str] = &[
    ".htm", ".html", ".jhtml", ".xhtml", ".shtml", ".php", ".asp", ".jsp", ".do", ".action",
    ".aspx", ".cfm", ".pl", ".cgi",
];

const STATIC_EXTENSIONS: &[&str] = &[
    ".js", ".json", ".map", ".mjs", ".cjs", ".jsx", ".vue", ".png", ".jpg", ".jpeg", ".gif",
    ".bmp", ".svg", ".webp", ".ico", ".tif", ".tiff", ".heic", ".apng", ".avif", ".psd", ".raw",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".zip", ".tar.gz", ".bak", ".config",
    ".swf",
];

const NOISE_JS_FILES: &[&str] = &["vendor", "chunk-vendors", "main", "polyfills"];

// 敏感信息检测
fn detect_sensitive_info(content: &str, base_url: &str) -> Vec<(String, String)> {
    let mut findings = Vec::new();

    // AK/SK
    let ak_sk_re =
        Regex::new(r#"["']?([a-zA-Z0-9_]+)\s*[=:]\s*["']([A-Za-z0-9\-]{16,64})["']"#).unwrap();
    for cap in ak_sk_re.captures_iter(content) {
        let var_name = cap[1].to_string();
        let value = cap[2].to_string();
        if (var_name.to_uppercase().contains("ACCESSKEY") ||
            var_name.to_uppercase().contains("SECRETKEY") ||
            var_name.to_uppercase().contains("AK") ||
            var_name.to_uppercase().contains("SK")) &&
            value.chars().any(|c| c.is_ascii_digit()) &&
            value.chars().any(|c| c.is_ascii())
        {
            findings.push(("AK/SK".to_string(), format!("{} = {}", var_name, value)));
        }
    }

    // 邮箱
    let email_re = Regex::new(r#""([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})""#).unwrap();
    for cap in email_re.captures_iter(content) {
        let email = cap[1].to_string();
        if !STATIC_EXTENSIONS.iter().any(|ext| email.ends_with(ext)) {
            let country = match email.split('.').last().unwrap_or("") {
                "cn" => "中国",
                "jp" => "日本",
                "uk" => "英国",
                _ => "未知",
            };
            findings.push(("邮箱".to_string(), format!("{} ({})", email, country)));
        }
    }

    // 手机号
    let phone_re = Regex::new(r#""(1[3-9]\d{9})""#).unwrap();
    for cap in phone_re.captures_iter(content) {
        let phone = cap[1].to_string();
        let operator = match &phone[0..3] {
            "134" | "135" | "136" | "137" | "138" | "139" | "147" | "148" | "150" | "151"
            | "152" | "157" | "158" | "159" | "165" | "172" | "178" | "182" | "183" | "184"
            | "187" | "188" | "195" | "197" | "198" => "中国移动",
            "133" | "149" | "153" | "173" | "174" | "177" | "180" | "181" | "189" | "190"
            | "191" => "中国电信",
            "130" | "131" | "132" | "145" | "146" | "155" | "156" | "166" | "171" | "175"
            | "176" | "185" | "186" | "196" | "199" => "中国联通",
            "162" => "中国电信虚拟运营商",
            "167" => "中国联通虚拟运营商",
            "192" => "中国广电",
            "170" => "虚拟运营商",
            _ => "未知运营商",
        };
        findings.push(("手机号".to_string(), format!("{} ({})", phone, operator)));
    }

    // Token
    let token_re = Regex::new(r#""(token|auth_token|bearer)\s*([A-Za-z0-9\-_]{16,128})""#).unwrap();
    for cap in token_re.captures_iter(content) {
        findings.push(("Token".to_string(), cap[0].to_string()));
    }

    // APIKey
    let apikey_re = Regex::new(r#""apikey\s*([A-Za-z0-9\-_]{16,64})""#).unwrap();
    for cap in apikey_re.captures_iter(content) {
        findings.push(("APIKey".to_string(), cap[1].to_string()));
    }

    // JDBC连接
    let jdbc_re = Regex::new(r#""(jdbc:[a-z]+://[a-zA-Z0-9.-]+:[0-9]+/[a-zA-Z0-9_]+)""#).unwrap();
    for cap in jdbc_re.captures_iter(content) {
        findings.push(("JDBC连接".to_string(), cap[1].to_string()));
    }

    // 密码
    let password_re = Regex::new(r#""password\s*=\s*([A-Za-z0-9!@#$%^&*]{8,32})""#).unwrap();
    for cap in password_re.captures_iter(content) {
        findings.push(("密码".to_string(), cap[1].to_string()));
    }

    // WebSocket接口
    let ws_re = Regex::new(r#""((ws|wss)://[a-zA-Z0-9.-]+(:[0-9]{1,5})?(/[^\"\n]*)?)""#).unwrap();
    for cap in ws_re.captures_iter(content) {
        findings.push(("WebSocket接口".to_string(), cap[1].to_string()));
    }

    // 备份文件和配置文件
    let backup_re =
        Regex::new(r#"["']([^"\s;}{><\p{Han}]+\.(?:zip|tar\.gz|bak|config))["']"#).unwrap();
    for cap in backup_re.captures_iter(content) {
        let path = cap[1].to_string();
        let full_url = normalize_url_for_crawl(&path, base_url);
        let file_type = if path.ends_with(".config") {
            "配置文件"
        } else {
            "备份文件"
        };
        findings.push((file_type.to_string(), full_url));
    }

    findings
}

// 提取域名
fn extract_domain(url: &str) -> Option<String> {
    let url = url.trim();
    if url.starts_with("http://") || url.starts_with("https://") {
        let without_scheme = url.replacen("http://", "", 1).replacen("https://", "", 1);
        let parts: Vec<&str> = without_scheme.split('/').collect();
        if !parts.is_empty() && !parts[0].contains('@') {
            return Some(parts[0].to_string());
        }
    }
    None
}

// 爬取用的URL规范化
fn normalize_url_for_crawl(path: &str, base_url: &str) -> String {
    if path.starts_with("http") || path.starts_with("ws") {
        path.to_string()
    } else {
        let base = Url::parse(base_url).expect("Invalid base URL");
        let full_url = base.join(path).expect("Invalid path");
        println!(
            "{} {}",
            "[*]拼接URL(爬取):".yellow(),
            full_url.as_str().yellow()
        );
        full_url.to_string()
    }
}

// API拼接用的URL处理
fn normalize_url_for_api(path: &str, base_url: &str, api_core: &str) -> String {
    // 排除 Base64 编码字符串
    if path.contains("data:")
        || path.contains("base64")
        || path
            .chars()
            .filter(|&c| c == '+' || c == '/' || c == '=')
            .count()
            > 5
        || path.len() > 100
    {
        println!("{} {}", "[*]跳过Base64路径:".red(), path.red());
        return String::new();
    }

    // 验证路径是否合法
    let cleaned = urlencoding::decode(path)
        .unwrap_or(path.to_string().into())
        .into_owned();

    let (path_part, query_part) = cleaned.split_once('?').unwrap_or((&cleaned, ""));
    let has_query = !query_part.is_empty();

    // 排除明显非 API 路径
    if path_part.contains("image")
        || cleaned.contains("img")
        || cleaned.contains("css")
        || cleaned.contains("font")
        || cleaned.contains("svg")
        || STATIC_EXTENSIONS.iter().any(|ext| cleaned.ends_with(ext))
        || cleaned.contains("swf")
        || (has_query && STATIC_EXTENSIONS.iter().any(|ext| path_part.contains(ext)))
        || cleaned
            .chars()
            .filter(|&c| c == '/' || c == '+' || c == '=')
            .count()
            > 10
    {
        println!("{} {}", "[*]非API路径:".red(), cleaned.red());
        return String::new();
    }

    let full_url = if path.starts_with("http") || path.starts_with("ws") {
        cleaned
    } else {
        let base = if base_url.ends_with('/') {
            base_url.to_string()
        } else {
            format!("{}/", base_url)
        };
        let cleaned_path = cleaned.trim_start_matches('/');
        if cleaned_path == "api"
            || cleaned_path == "api/"
            || cleaned_path == "/api"
            || cleaned_path == "/api/"
        {
            format!("{}{}", base, api_core.trim_matches('/'))
        } else {
            format!("{}{}", base, cleaned_path)
        }
    };

    // 验证 URL 是否合法
    if Url::parse(&full_url).is_err() {
        println!("{} {}", "[*]无效URL:".red(), full_url.red());
        return String::new();
    }

    full_url
}

// 抓取url
fn crawl_url(
    client: &reqwest::blocking::Client,
    url: &str,
    base_url: &str,
    depth: u8,
    visited: &mut HashSet<String>,
    html_urls: &mut Vec<String>,
    static_urls: &mut Vec<String>,
    sensitive_info: &mut Vec<(String, String)>,
    is_third_party: bool,
    blacklist: &[String],
    domains: &mut HashSet<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if (depth > 3 && !is_third_party) || (depth > 1 && is_third_party) || visited.contains(url) {
        return Ok(());
    }

    if is_blacklisted(url, blacklist) {
        println!("{} {}", "[*]黑名单域名跳过:".red(), url.red());
        return Ok(());
    }

    visited.insert(url.to_string());
    let base_domain = extract_domain(base_url).unwrap_or_default();

    match client.get(url).send() {
        Ok(response) if response.status().is_success() => {
            let html_content = response.text()?;
            sensitive_info.extend(detect_sensitive_info(&html_content, base_url));

            let src_href_regex = Regex::new(r#"(?i)(src|href)=["']([^"']+)["']"#)?;
            for cap in src_href_regex.captures_iter(&html_content) {
                let value = &cap[2];
                let full_url = normalize_url_for_crawl(value, base_url);
                println!(
                    "{} {}",
                    "[*]正则提取URL:".truecolor(255, 250, 205),
                    full_url.truecolor(255, 250, 205)
                );
                if let Some(domain) = extract_domain(&full_url) {
                    domains.insert(domain);
                }
                if let Some(domain) = extract_domain(&full_url) {
                    if domain != base_domain {
                        println!("{} {}", "[!]疑似第三方URL:".purple(), full_url.purple());
                        if !is_third_party && !is_blacklisted(&full_url, blacklist) {
                            crawl_url(
                                client,
                                &full_url,
                                &full_url,
                                1,
                                visited,
                                html_urls,
                                static_urls,
                                sensitive_info,
                                true,
                                blacklist,
                                domains,
                            )?;
                        }
                    } else {
                        classify_url(&full_url, html_urls, static_urls);
                        if full_url.ends_with('/') && depth < 3 && !is_third_party {
                            crawl_url(
                                client,
                                &full_url,
                                base_url,
                                depth + 1,
                                visited,
                                html_urls,
                                static_urls,
                                sensitive_info,
                                false,
                                blacklist,
                                domains,
                            )?;
                        }
                    }
                }
            }

            let document = Html::parse_document(&html_content);
            let src_selector = Selector::parse("[src]").unwrap();
            let href_selector = Selector::parse("[href]").unwrap();

            for element in document
                .select(&src_selector)
                .chain(document.select(&href_selector))
            {
                if let Some(value) = element.value().attr("src").or(element.value().attr("href")) {
                    let full_url = normalize_url_for_crawl(value, base_url);
                    println!(
                        "{} {}",
                        "[*]目标提取URL:".truecolor(255, 250, 205),
                        full_url.truecolor(255, 250, 205)
                    );
                    if let Some(domain) = extract_domain(&full_url) {
                        domains.insert(domain);
                    }
                    if let Some(domain) = extract_domain(&full_url) {
                        if domain != base_domain {
                            println!("{} {}", "[!]疑似第三方URL:".purple(), full_url.purple());
                            if !is_third_party && !is_blacklisted(&full_url, blacklist) {
                                crawl_url(
                                    client,
                                    &full_url,
                                    &full_url,
                                    1,
                                    visited,
                                    html_urls,
                                    static_urls,
                                    sensitive_info,
                                    true,
                                    blacklist,
                                    domains,
                                )?;
                            }
                        } else {
                            classify_url(&full_url, html_urls, static_urls);
                            if full_url.ends_with('/') && depth < 3 && !is_third_party {
                                crawl_url(
                                    client,
                                    &full_url,
                                    base_url,
                                    depth + 1,
                                    visited,
                                    html_urls,
                                    static_urls,
                                    sensitive_info,
                                    false,
                                    blacklist,
                                    domains,
                                )?;
                            }
                        }
                    }
                }
            }

            let iframe_selector = Selector::parse("iframe").unwrap();
            for iframe in document.select(&iframe_selector) {
                if let Some(src) = iframe.value().attr("src") {
                    let full_url = normalize_url_for_crawl(src, base_url);
                    println!(
                        "{} {}",
                        "[*]iframe提取URL:".truecolor(255, 250, 205),
                        full_url.truecolor(255, 250, 205)
                    );
                    if let Some(domain) = extract_domain(&full_url) {
                        domains.insert(domain);
                    }
                    if let Some(domain) = extract_domain(&full_url) {
                        if domain != base_domain {
                            println!("{} {}", "[!]疑似第三方URL:".purple(), full_url.purple());
                            if !is_third_party && !is_blacklisted(&full_url, blacklist) {
                                crawl_url(
                                    client,
                                    &full_url,
                                    &full_url,
                                    1,
                                    visited,
                                    html_urls,
                                    static_urls,
                                    sensitive_info,
                                    true,
                                    blacklist,
                                    domains,
                                )?;
                            }
                        } else {
                            classify_url(&full_url, html_urls, static_urls);
                            if full_url.ends_with('/') && depth < 3 && !is_third_party {
                                crawl_url(
                                    client,
                                    &full_url,
                                    base_url,
                                    depth + 1,
                                    visited,
                                    html_urls,
                                    static_urls,
                                    sensitive_info,
                                    false,
                                    blacklist,
                                    domains,
                                )?;
                            }
                        }
                    }
                }
            }
        }
        Err(e) => println!("{} {} - {}", "访问失败:".red(), url, e.to_string().red()),
        _ => {}
    }
    Ok(())
}

// URL分类
fn classify_url(url: &str, html_urls: &mut Vec<String>, static_urls: &mut Vec<String>) {
    if HTML_EXTENSIONS.iter().any(|ext| url.ends_with(ext)) {
        html_urls.push(url.to_string());
    } else if STATIC_EXTENSIONS.iter().any(|ext| url.ends_with(ext)) {
        static_urls.push(url.to_string());
    }
}

// API过滤
fn filter_api_path(path: &str, base_urls: &[String], api_core: &str, noise_strings: &[String]) -> Vec<String> {
    let trimmed = path.trim();
    println!(
        "{} {}",
        "[*]检查路径:".truecolor(128, 128, 128),
        trimmed.truecolor(128, 128, 128)
    );

    // 排除 Base64 编码字符串
    if trimmed.contains("data:")
        || trimmed.contains("base64")
        || trimmed
            .chars()
            .filter(|&c| c == '+' || c == '/' || c == '=')
            .count()
            > 5
        || trimmed.len() > 100
    {
        println!("{} {}", "[*]Base64字符串过滤:".red(), trimmed.red());
        return vec![];
    }

    // 排除长度不符合的路径
    if trimmed.len() < 2 || trimmed.len() > 500 {
        println!("{} {}", "[*]路径长度不符合:".red(), trimmed.red());
        return vec![];
    }

    // 排除包含中文的路径
    let chinese_re = Regex::new(r"\p{Han}").unwrap();
    if chinese_re.is_match(trimmed) {
        println!("{} {}", "[*]包含中文过滤:".red(), trimmed.red());
        return vec![];
    }

    // 排除噪音字符串
    if noise_strings.iter().any(|noise| trimmed.contains(noise))
        || trimmed.contains("<?")
        || trimmed.contains("?>")
        || trimmed.contains("</")
        || trimmed.starts_with("/#")
        || trimmed.contains("/g,c=r(")
        || trimmed.contains("schemeClr")
        || trimmed.contains("'>")
        || trimmed.contains("<a:")
        || trimmed.contains("</a:")
        || trimmed.contains("length")
        || trimmed.contains("\\")
    {
        println!("{} {}", "[*]垃圾字符串过滤:".red(), trimmed.red());
        return vec![];
    }

    let cleaned = urlencoding::decode(trimmed)
        .unwrap_or(trimmed.to_string().into())
        .into_owned();

    let (path_part, query_part) = cleaned.split_once('?').unwrap_or((&cleaned, ""));
    let has_query = !query_part.is_empty();

    if path_part.contains("image")
        || path_part.contains("img")
        || path_part.contains("css")
        || path_part.contains("font")
        || path_part.contains("svg")
        || path_part.contains("swf")
        || path_part.contains("ttf")
        || STATIC_EXTENSIONS.iter().any(|ext| path_part.ends_with(ext))
    {
        println!("{} {}", "[*]排除资源类路径:".red(), cleaned.red());
        return vec![];
    }

    if has_query && STATIC_EXTENSIONS.iter().any(|ext| path_part.contains(ext)) {
        println!("{} {}", "[*]排除带查询参数的静态资源:".red(), cleaned.red());
        return vec![];
    }

    let is_explicit_api = path_part == "api"
        || path_part == "api/"
        || path_part == "/api"
        || path_part == "/api/"
        || path_part.starts_with("api/")
        || path_part.contains("/api/")
        || (path_part.contains("/api/") && path_part.split("/").count() > 2);

    let is_restful_path = path_part.starts_with("/")
        && path_part.split("/").count() >= 2
        && !path_part.contains(".")
        && path_part
            .chars()
            .all(|c| c.is_alphanumeric() || c == '/' || c == '-' || c == '_');

    if !is_explicit_api && !is_restful_path {
        println!("{} {}", "[*]非API路径:".red(), cleaned.red());
        return vec![];
    }

    println!("{} {:?}", "[*]使用base_urls:".cyan(), base_urls);
    let mut results = Vec::new();
    for base in base_urls {
        let full_url = normalize_url_for_api(&cleaned, base, api_core);
        if !full_url.is_empty() {
            if is_explicit_api {
                println!("{} {}", "[*]API:".green(), full_url.green());
            } else if is_restful_path {
                println!("{} {}", "[!]疑似RESTful接口:".purple(), full_url.purple());
            }
            results.push(full_url);
        }
    }
    results
}

// 黑名单检查
fn is_blacklisted(url: &str, blacklist: &[String]) -> bool {
    if let Some(domain) = extract_domain(url) {
        blacklist.iter().any(|black| domain.contains(black))
    } else {
        false
    }
}

// 噪音JS检查
fn is_noise_js_file(url: &str) -> bool {
    let file_name = url.split('/').last().unwrap_or("");
    NOISE_JS_FILES
        .iter()
        .any(|&noise| file_name.starts_with(noise))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 || args[1] != "-u" {
        println!("Usage: web_scraper -u <Target_URL> [-c \"Cookie\"] [-a \"Authorization\"]");
        println!("");
        return Ok(());
    }

    let base_url = args[2].split('#').next().unwrap_or(&args[2]).to_string();
    if !base_url.starts_with("http") {
        println!("请提供完整的URL，例如 https://example.com");
        return Ok(());
    }

    let mut cookie = None;
    let mut auth = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "-c" => {
                if i + 1 < args.len() {
                    cookie = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    println!("缺少 Cookie 值");
                    return Ok(());
                }
            }
            "-a" => {
                if i + 1 < args.len() {
                    auth = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    println!("缺少 Authorization 值");
                    return Ok(());
                }
            }
            _ => {
                println!("[*]未知参数: {}", args[i]);
                return Ok(());
            }
        }
    }

    // 加载配置
    let config = config::Config::load();
    println!("{} {:?}", "[*]加载的黑名单:".cyan(), config.blacklist);
    println!("{} {}", "[*]加载的api_core:".cyan(), config.api_core.cyan());
    println!("{} {:?}", "[*]加载的noise_strings:".cyan(), config.noise_strings);

    let mut client_builder = ClientBuilder::new().danger_accept_invalid_certs(true);
    if let Some(cookie_value) = cookie {
        client_builder = client_builder.default_headers({
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert("Cookie", cookie_value.parse()?);
            headers
        });
    }
    if let Some(auth_value) = auth {
        client_builder = client_builder.default_headers({
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert("Authorization", auth_value.parse()?);
            headers
        });
    }
    let client = client_builder.build()?;

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
            .template("{spinner:.yellow} {msg}")
            .unwrap(),
    );
    spinner.enable_steady_tick(Duration::from_millis(100));

    let mut html_urls = Vec::new();
    let mut static_urls = Vec::new();
    let mut visited = HashSet::new();
    let mut sensitive_info = Vec::new();
    let mut domains = HashSet::new();

    spinner.set_message(format!(
        "{} {}",
        "正在请求URL:".bright_blue(),
        base_url.green()
    ));
    crawl_url(
        &client,
        &base_url,
        &base_url,
        1,
        &mut visited,
        &mut html_urls,
        &mut static_urls,
        &mut sensitive_info,
        false,
        &config.blacklist,
        &mut domains,
    )?;

    html_urls.sort();
    html_urls.dedup();
    static_urls.sort();
    static_urls.dedup();

    println!("{}", "\n=== HTML 页面类 ===".cyan());
    for url in &html_urls {
        println!("{}", url.truecolor(255, 250, 205));
    }
    println!("{}", "\n=== 静态资源类 ===".cyan());
    for url in &static_urls {
        println!("{}", url.truecolor(255, 250, 205));
    }
    println!(
        "{} {}",
        "[*]static_urls大小:".yellow(),
        static_urls.len().to_string().yellow()
    );

    let temp_dir = TempDir::new("js_files")?;
    println!(
        "{} {:?}",
        "\n临时文件夹创建于:".truecolor(255, 215, 0),
        temp_dir.path()
    );

    let mut raw_api_paths = Vec::new();
    let mut base_urls = vec![base_url.clone()];
    let base_domain = extract_domain(&base_url).unwrap_or_default();

    // 提取JS中的URL（只限主域名）
    spinner.set_message("提取JS中的基础URL...");
    for url in &static_urls {
        if url.ends_with(".js") && !is_noise_js_file(url) {
            if extract_domain(url).unwrap_or_default() != base_domain {
                println!("{} {}", "[*]跳过非主域名JS:".red(), url.red());
                continue;
            }
            println!("{} {}", "[*]准备处理JS:".green(), url.green());
            match client.get(url).send() {
                Ok(js_response) if js_response.status().is_success() => {
                    let js_content = js_response.text()?;
                    sensitive_info.extend(detect_sensitive_info(&js_content, &base_url));

                    let file_name = url.split('/').last().unwrap_or("temp.js");
                    let file_path = temp_dir.path().join(file_name);
                    let mut file = File::create(&file_path)?;
                    file.write_all(js_content.as_bytes())?;

                    println!("{} {}", "[*]解析JS文件:".yellow(), url.yellow());
                    let url_re = Regex::new(r#"(https?://[^\s'"]+)"#)?;
                    for cap in url_re.captures_iter(&js_content) {
                        let extracted_url = cap[1].to_string();
                        println!("{} {}", "[*]尝试提取URL:".yellow(), extracted_url.yellow());
                        if let Some(domain) = extract_domain(&extracted_url) {
                            domains.insert(domain);
                        }
                        if !is_blacklisted(&extracted_url, &config.blacklist)
                            && !base_urls.contains(&extracted_url)
                        {
                            if extract_domain(&extracted_url).unwrap_or_default() == base_domain {
                                println!("{} {}", "[*]添加基础URL:".green(), extracted_url.green());
                                base_urls.push(extracted_url);
                            } else {
                                println!("{} {}", "[*]跳过非主域名URL:".red(), extracted_url.red());
                            }
                        } else {
                            println!(
                                "{} {}",
                                "[*]跳过重复或黑名单URL:".red(),
                                extracted_url.red()
                            );
                        }
                    }
                }
                Err(e) => println!(
                    "{} {} - {}",
                    "[*]JS文件访问失败:".red(),
                    url.red(),
                    e.to_string().red()
                ),
                _ => {}
            }
        } else {
            println!("{} {}", "[*]跳过非JS或噪音文件:".red(), url.red());
        }
    }

    println!("{} {:?}", "[*]最终base_urls:".cyan(), base_urls);

    // 提取拼接API路徑
    spinner.set_message("解析JS中的接口地址...");
    for url in &static_urls {
        if url.ends_with(".js") && !is_noise_js_file(url) {
            if extract_domain(url).unwrap_or_default() != base_domain {
                continue;
            }
            println!("{} {}", "[*]准备处理JS:".green(), url.green());
            match client.get(url).send() {
                Ok(js_response) if js_response.status().is_success() => {
                    let js_content = js_response.text()?;
                    let api_regex = Regex::new(
                        r#"(?:["']|/)(/[^"\s;}{><\p{Han}]+|api/?(?:[^"\s;}{><\p{Han}]+)?)(?:["']|/)?(?:[^"\s;}{><\p{Han}]*)"#,
                    )?;
                    for cap in api_regex.captures_iter(&js_content) {
                        let path = cap[1].to_string();
                        println!("{} {}", "[*]提取相对路径:".blue(), path.blue());
                        let mut apis = filter_api_path(&path, &base_urls, &config.api_core, &config.noise_strings);
                        println!("{} {:?}", "[*]拼接结果:".green(), apis);
                        raw_api_paths.append(&mut apis);
                    }
                }
                Err(e) => println!(
                    "{} {} - {}",
                    "[*]JS文件访问失败:".red(),
                    url.red(),
                    e.to_string().red()
                ),
                _ => {}
            }
        }
    }

    let mut api_urls = Vec::new();
    for path in &raw_api_paths {
        api_urls.push(path.clone());
    }
    api_urls.sort();
    api_urls.dedup();

    spinner.finish_with_message("[*]JS接口提取完成");

    println!(
        "{}",
        "\n=== 从JS文件中提取的接口地址 ===".truecolor(87, 182, 194)
    );
    for url in &api_urls {
        println!("{}", url);
    }

    let mut all_urls = Vec::new();
    all_urls.extend(html_urls.iter().cloned());
    all_urls.extend(static_urls.iter().cloned());
    all_urls.extend(api_urls.iter().cloned());
    all_urls.sort();
    all_urls.dedup();

    let pb = ProgressBar::new(all_urls.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{msg} [{elapsed_precise:.truecolor(255,165,0)}] [{bar:40.yellow/bright_black}] {pos}/{len} ({eta:.truecolor(255,165,0)})")
            .unwrap()
            .progress_chars("█ ")
    );
    pb.set_message("[*]访问URL中...");

    let mut results: Vec<String> = Vec::new();
    for url in &all_urls {
        if is_blacklisted(url, &config.blacklist) {
            println!("{} {}", "[*]黑名单URL跳过:".red(), url.red());
            continue;
        }
        match client.get(url).send() {
            Ok(api_response) => {
                let status_code = api_response.status().as_u16();
                let content_length = api_response
                    .headers()
                    .get("content-length")
                    .map_or("N/A".to_string(), |v| {
                        v.to_str().unwrap_or("N/A").to_string()
                    });

                let status_text = format!("Code: {}", status_code);
                let length_text = format!("Length: {}", content_length);
                let url_text = format!("URL: {}", url);

                let colored_result = match status_code {
                    200 => format!(
                        "{} {} {}",
                        status_text.green(),
                        length_text.green(),
                        url_text.green()
                    ),
                    302 => format!(
                        "{} {} {}",
                        status_text.purple(),
                        length_text.purple(),
                        url_text.purple()
                    ),
                    401 | 403 => format!(
                        "{} {} {}",
                        status_text.yellow(),
                        length_text.yellow(),
                        url_text.yellow()
                    ),
                    404 => format!(
                        "{} {} {}",
                        status_text.blue(),
                        length_text.blue(),
                        url_text.blue()
                    ),
                    500..=599 => format!(
                        "{} {} {}",
                        status_text.red(),
                        length_text.red(),
                        url_text.red()
                    ),
                    _ => format!("{} {} {}", status_text, length_text, url_text),
                };
                results.push(colored_result);
            }
            Err(e) => results.push(format!(
                "{} {} - {}",
                "[*]访问失败: ".red(),
                url.red(),
                e.to_string().red()
            )),
        }
        pb.inc(1);
    }

    pb.finish_with_message("探测URL存活完成");
    println!("{}", "\n=== 所有URL访问结果 ===".truecolor(87, 182, 194));
    for result in &results {
        println!("{}", result);
    }

    // 打印去重后的域名列表
    println!(
        "{}",
        "\n=== 从JS和HTML中提取的去重域名 ===".truecolor(87, 182, 194)
    );
    if domains.is_empty() {
        println!("{}", "[*]未发现域名".truecolor(255, 215, 0));
    } else {
        let mut sorted_domains: Vec<String> = domains.into_iter().collect();
        sorted_domains.sort();
        for domain in sorted_domains {
            println!("{}", domain.truecolor(255, 250, 205));
        }
    }

    println!("\n=== 统计信息 ===");
    println!("[]提取到的URL总数: {}", all_urls.len());
    println!("[!]操作完成，临时文件夹已删除。");

    // 統一打印敏感信息表格
    println!("{}", "\n=== 检测到的敏感信息 ===".truecolor(255, 215, 0));
    if sensitive_info.is_empty() {
        println!("{}", "[*]未发现敏感信息".truecolor(255, 215, 0));
    } else {
        println!(
            "{:<5} | {:<10} | {}",
            "序号".truecolor(255, 215, 0),
            "类型".truecolor(255, 215, 0),
            "值".truecolor(255, 215, 0)
        );
        println!(
            "{}",
            "---------------------------------------------".truecolor(255, 215, 0)
        );
        for (i, (type_name, value)) in sensitive_info.iter().enumerate() {
            println!(
                "{:<5} | {:<10} | {}",
                (i + 1).to_string().truecolor(255, 215, 0),
                type_name.truecolor(255, 215, 0),
                value.truecolor(255, 215, 0)
            );
        }
    }

    let url_obj = Url::parse(&base_url)?;
    let domain = url_obj.host_str().unwrap_or("unknown").replace('.', "-");
    let output_dir = Path::new("output");
    fs::create_dir_all(output_dir)?;
    let csv_path = output_dir.join(format!("{}.csv", domain));
    let mut writer = Writer::from_path(&csv_path)?;

    writer.write_record(&["Code", "Length", "URL"])?;
    for result in &results {
        let parts: Vec<&str> = result.split_whitespace().collect();
        if parts.len() >= 6 {
            let code = parts[1];
            let length = parts[3];
            let url = parts[5..].join(" ");
            writer.write_record(&[code, length, &url])?;
        } else {
            writer.write_record(&["N/A", "N/A", result])?;
        }
    }
    writer.write_record(&["", "", ""])?;
    writer.write_record(&["序号", "类型", "值"])?;
    for (i, (type_name, value)) in sensitive_info.iter().enumerate() {
        writer.write_record(&[
            (i + 1).to_string(),
            type_name.to_string(),
            value.to_string(),
        ])?;
    }
    writer.flush()?;
    println!(
        "{} {}",
        "\n[*]结果已输出到".green(),
        csv_path.display().to_string().green()
    );

    Ok(())
}