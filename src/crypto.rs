//! WCDB 数据库首页密钥材料的派生与校验。
//!
//! 微信 4.x 只在内存/数据库层面保存账号 passphrase（32 字节随机值），
//! 不直接保存各库的原始密钥。每个数据库以自己的 16 字节 salt
//!（page1[0..16]）对 passphrase 做 256000 轮 PBKDF2-HMAC-SHA512 派生出 AES 密钥。
//! 首页末尾附有 HMAC-SHA512，用于校验页体完整性。

use crate::messages::{fail, msg};
use anyhow::ensure;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;

/// 数据库页固定大小。
pub const PAGE_SIZE: usize = 4096;
/// salt 固定长度。
pub const SALT_LEN: usize = 16;
/// 主密钥固定长度。
pub const KEY_LEN: usize = 32;
/// PBKDF2 派生轮数。
pub const KEY_ROUNDS: u32 = 256_000;
/// 密钥类型：32 字节数组。
pub type Key = [u8; KEY_LEN];
/// WCDB 的 mac salt 为数据库 salt 与该常量逐字节异或。
const MAC_SALT_XOR: u8 = 0x3A;

type HmacSha512 = Hmac<Sha512>;

/// enc_key → 首页 HMAC：先派生 mac_key（PBKDF2，2 轮，
/// salt⊕0x3A），再对页体 + 页号做 HMAC-SHA512。
/// 与 hook.py 的 `_matches` 保持一致（LLDB 回调仅支持 Python，
/// 无法复用 Rust 实现，两处需同步修改）。
fn page1_hmac_of(enc_key: &[u8], salt: &[u8], page1: &[u8]) -> [u8; 64] {
    // SALT_LEN 固定 16 字节，用栈上数组避免每次调用堆分配。
    let mut mac_salt = [0u8; SALT_LEN];
    for (i, b) in salt.iter().enumerate() {
        mac_salt[i] = b ^ MAC_SALT_XOR;
    }
    let mut mac_key = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha512>(enc_key, &mac_salt, 2, &mut mac_key);
    let mut mac = HmacSha512::new_from_slice(&mac_key).unwrap_or_else(|_| panic!("{}", msg(-506)));
    mac.update(&page1[SALT_LEN..PAGE_SIZE - 64]);
    mac.update(&1u32.to_le_bytes());
    mac.finalize().into_bytes().into()
}

/// 校验 32 字节 `passphrase` 是否能解开加密数据库的首页。
///
/// 兼容两种候选形态（与微信自身行为一致）：
/// passphrase 直接作为 enc_key，或先经 256000 轮 PBKDF 派生。
/// 返回 true 表示该 passphrase 可以解开此数据库。
pub fn verify_page1(passphrase: &Key, page1: &[u8]) -> bool {
    if page1.len() < PAGE_SIZE || page1.starts_with(b"SQLite format 3") {
        return false;
    }
    let salt = &page1[..SALT_LEN];
    let stored = &page1[PAGE_SIZE - 64..];
    let mut derived = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha512>(passphrase, salt, KEY_ROUNDS, &mut derived);
    [passphrase.as_slice(), derived.as_slice()]
        .iter()
        .any(|enc_key| page1_hmac_of(enc_key, salt, page1)[..] == stored[..])
}

/// 字节数组转小写十六进制字符串。
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// hex 字符 → nibble 值（0-15）；非法字符返回 None。
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// 解析 64 位十六进制 passphrase（-106：格式无效）。
pub fn from_hex(s: &str) -> anyhow::Result<Vec<u8>> {
    let s = s.trim();
    ensure!(s.len() == KEY_LEN * 2, fail(-106));
    let mut out = Vec::with_capacity(KEY_LEN);
    for chunk in s.as_bytes().chunks_exact(2) {
        let hi = hex_nibble(chunk[0]).ok_or_else(|| fail(-106))?;
        let lo = hex_nibble(chunk[1]).ok_or_else(|| fail(-106))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

/// 仅供测试：构造合成加密数据库首页（passphrase 即 enc_key 形态）。
#[cfg(test)]
pub(crate) mod synth {
    use super::*;

    pub fn page1(passphrase: &Key, salt: [u8; SALT_LEN]) -> [u8; PAGE_SIZE] {
        let mut page1 = [0u8; PAGE_SIZE];
        page1[..SALT_LEN].copy_from_slice(&salt);
        let digest = page1_hmac_of(passphrase, &salt, &page1);
        page1[PAGE_SIZE - 64..].copy_from_slice(&digest);
        page1
    }
}

#[cfg(test)]
mod tests {
    use super::synth::page1 as make_page1;
    use super::*;

    #[test]
    fn passphrase_as_key_verifies() {
        let passphrase = [7u8; KEY_LEN];
        let page1 = make_page1(&passphrase, [1u8; SALT_LEN]);
        assert!(verify_page1(&passphrase, &page1));
    }

    #[test]
    fn derived_key_shape_verifies() {
        // 仅经 256000 轮派生形态才能通过校验的 passphrase。
        let passphrase = [9u8; KEY_LEN];
        let salt = [2u8; SALT_LEN];
        let mut derived = [0u8; KEY_LEN];
        pbkdf2_hmac::<Sha512>(&passphrase, &salt, KEY_ROUNDS, &mut derived);
        let page1 = make_page1(&derived, salt);
        assert!(verify_page1(&passphrase, &page1));
    }

    #[test]
    fn wrong_key_rejected() {
        let passphrase = [7u8; KEY_LEN];
        let page1 = make_page1(&passphrase, [1u8; SALT_LEN]);
        assert!(!verify_page1(&[8u8; KEY_LEN], &page1));
    }

    #[test]
    fn plaintext_db_rejected() {
        let mut page1 = [0u8; PAGE_SIZE];
        page1[..15].copy_from_slice(b"SQLite format 3");
        assert!(!verify_page1(&[0u8; KEY_LEN], &page1));
    }

    #[test]
    fn from_hex_accepts_valid_64_hex() {
        let hex = to_hex(&[0xa3; KEY_LEN]);
        assert_eq!(from_hex(&hex).unwrap(), vec![0xa3; KEY_LEN]);
    }

    #[test]
    fn from_hex_rejects_bad_input() {
        // 错误长度。
        assert!(from_hex("a3f5").is_err());
        // 非十六进制字符。
        assert!(from_hex(&to_hex(&[0xa3; KEY_LEN]).replace('a', "g")).is_err());
    }
}
