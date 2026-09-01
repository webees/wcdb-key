//! Windows 捕获：直接读取运行中的微信进程内存。
//!
//! 策略：找 `com.Tencent.WCDB.Config.Cipher` 字符串 → 构造 (addr,len) 对
//! 模式 → 全内存找引用 → 从引用点解引用对象链 → 读 Config.Cipher 的 Data blob
//! → XOR 解码 → 提取键值候选 → HMAC 校验。
//!
//! 参考 wcdb-key-tool（TANGandXUE）的 Windows 方案，该方法在 4.1.13.12
//! 实测通过（19/19 库全量 HMAC 校验）。若未来版本变更对象布局或掩码，
//! 可能需要调整偏移常量与 `XOR_MASK`。

use anyhow::{ensure, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

use crate::crypto::{self, Key, KEY_LEN};
use crate::messages::*;
use crate::shared::{parallel_chunks, AccountData, CaptureResult};

const CIPHER_CONFIG_NAME: &[u8] = b"com.Tencent.WCDB.Config.Cipher";
const READ_CHUNK: usize = 8 * 1024 * 1024;
const PROCESS_NAMES: [&str; 2] = ["weixin.exe", "wechat.exe"];

/// 每库 key 映射条目：数据库路径 → 64 位 hex key。
type DbKeyEntry = (PathBuf, String);

/// 对象链解引偏移量（WCDB Config.Cipher 对象布局，版本相关）。
const NODE_OFFSET: usize = 0x10; // 引用地址到 node 基址
const CONFIG_PTR_OFFSET: usize = 0x28; // node 内 config 指针偏移
const DATA_OFFSET: usize = 0x88; // config 对象内 Data 成员偏移
const DATA_PTR_FIELD: usize = 0x08; // Data 对象内 data_ptr 偏移
const DATA_LEN_FIELD: usize = 0x10; // Data 对象内 data_len 偏移

/// XOR 掩码，取自 wcdb-key-tool v4.1.11（由 WeChatWin.dll 的代码字节推导而来）。
const WINDOWS_CONFIG_XOR_MASK: &[u8] = &[
    0xd2, 0xc7, 0x44, 0x24, 0x58, 0x02, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x50, 0x48, 0x8b,
    0x45, 0x00, 0x48, 0x84, 0x4c, 0x24, 0x48, 0x48, 0x89, 0x44, 0x25, 0x40, 0x48, 0x58, 0x4c, 0x24,
];

/// 返回 Windows 微信数据根目录（xwechat_files）。
pub fn default_db_root() -> Option<PathBuf> {
    let home = crate::shared::home_dir().ok()?;
    [
        home.join("Documents/xwechat_files"),
        home.join("AppData/Roaming/Tencent/xwechat_files"),
    ]
    .into_iter()
    .find(|p| p.is_dir())
}

struct HandleGuard(HANDLE);
impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn find_wechat_pids() -> Result<Vec<u32>> {
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE {
        return Err(fail(-300));
    }
    let _snap = HandleGuard(snap);
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    ensure!(
        unsafe { Process32FirstW(snap, &mut entry) } != 0,
        fail(-300)
    );
    let mut pids = Vec::new();
    loop {
        // 进程名解码（UTF-16 → 小写）为纯逻辑，移出 unsafe 块。
        let name = String::from_utf16_lossy(
            &entry.szExeFile[..entry
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExeFile.len())],
        )
        .to_lowercase();
        if PROCESS_NAMES.contains(&name.as_str()) {
            pids.push(entry.th32ProcessID);
        }
        if unsafe { Process32NextW(snap, &mut entry) } == 0 {
            break;
        }
    }
    Ok(pids)
}

fn read_remote(handle: HANDLE, addr: usize, size: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; size];
    let mut read = 0usize;
    let ok = unsafe {
        ReadProcessMemory(
            handle,
            addr as *const _,
            buf.as_mut_ptr() as *mut _,
            size,
            &mut read,
        )
    };
    (ok != 0 && read > 0).then(|| {
        buf.truncate(read);
        buf
    })
}

fn read_remote_u64(handle: HANDLE, addr: usize) -> Option<u64> {
    let b = read_remote(handle, addr, 8)?;
    (b.len() >= 8).then(|| u64::from_le_bytes(b[..8].try_into().unwrap()))
}

/// 在 `buf` 中搜索 `needle` 全部位置，返回绝对地址。
pub(crate) fn find_hits(buf: &[u8], base: usize, needle: &[u8]) -> Vec<usize> {
    let mut hits = Vec::new();
    let Some(&first) = needle.first() else {
        return hits;
    };
    let mut from = 0usize;
    while let Some(rel) = memchr::memchr(first, &buf[from..]) {
        let at = from + rel;
        if buf[at..].starts_with(needle) {
            hits.push(base + at);
        }
        from = at + 1;
    }
    hits
}

/// 枚举所有可读区域的块，对每块调用 `f(&hay, hay_addr)`；`f` 返回 false 提前终止。
fn for_each_region_chunk<F>(handle: HANDLE, f: &mut F) -> Result<()>
where
    F: FnMut(&[u8], usize) -> bool,
{
    let mut addr = 0usize;
    loop {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe {
            VirtualQueryEx(
                handle,
                addr as *const _,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        } == 0
        {
            break;
        }
        let base = mbi.BaseAddress as usize;
        let size = mbi.RegionSize;
        if size == 0 {
            break;
        }
        let next = match base.checked_add(size) {
            Some(n) => n,
            None => break,
        };
        if mbi.State == MEM_COMMIT
            && (mbi.Protect & PAGE_GUARD) == 0
            && mbi.Protect != PAGE_NOACCESS
        {
            let mut carry: Vec<u8> = Vec::new();
            let mut chunk_base = base;
            while chunk_base < base + size {
                let want = (base + size - chunk_base).min(READ_CHUNK);
                let Some(mut buf) = read_remote(handle, chunk_base, want) else {
                    break;
                };
                let read_len = buf.len();
                let mut hay = std::mem::take(&mut carry);
                let hay_addr = chunk_base - hay.len();
                hay.append(&mut buf);
                if !f(&hay, hay_addr) {
                    return Ok(());
                }
                let keep = (CIPHER_CONFIG_NAME.len() - 1).min(hay.len());
                carry = hay[hay.len() - keep..].to_vec();
                chunk_base += read_len;
                if read_len < want {
                    break;
                }
            }
        }
        addr = next;
    }
    Ok(())
}

/// 遍历全部可读内存块，用 `scan` 收集每块产生的命中地址。
/// 任一块在扫描前超过 `deadline` 即视为整体超时，返回 -305。
fn scan_regions<T, F>(handle: HANDLE, deadline: Instant, mut scan: F) -> Result<Vec<T>>
where
    F: FnMut(&[u8], usize) -> Vec<T>,
{
    let mut hits = Vec::new();
    let mut timed_out = false;
    for_each_region_chunk(handle, &mut |hay, hay_addr| {
        if Instant::now() > deadline {
            timed_out = true;
            return false;
        }
        hits.extend(scan(hay, hay_addr));
        true
    })?;
    if timed_out {
        return Err(fail(-305));
    }
    Ok(hits)
}

/// 构建 16 字节 pair pattern：(addr as u64 LE) + (len as u64 LE)
fn pair_pattern(addr: u64, len: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(16);
    p.extend_from_slice(&addr.to_le_bytes());
    p.extend_from_slice(&len.to_le_bytes());
    p
}

/// 读取 config object 链，返回 XOR 解码后的候选 key 列表。
fn read_config_keys(handle: HANDLE, ref_addr: usize) -> Vec<Vec<u8>> {
    // node = ref_addr 减去 NODE_OFFSET（引用地址到 node 基址的偏移）
    // config_ptr = node + CONFIG_PTR_OFFSET 处的 8 字节指针
    // 从 config_ptr + DATA_OFFSET 读 Data 对象。
    let node_addr = ref_addr.wrapping_sub(NODE_OFFSET);
    let config_ptr = match read_remote_u64(handle, node_addr + CONFIG_PTR_OFFSET) {
        Some(p) if p != 0 => p as usize,
        _ => return Vec::new(),
    };
    // 读取 Data 对象：data_ptr 位于 +DATA_PTR_FIELD，data_len 位于 +DATA_LEN_FIELD。
    let data_mem = match read_remote(handle, config_ptr + DATA_OFFSET, 24) {
        Some(d) if d.len() >= 24 => d,
        _ => return Vec::new(),
    };
    let data_ptr = u64::from_le_bytes(
        data_mem[DATA_PTR_FIELD..DATA_PTR_FIELD + 8]
            .try_into()
            .unwrap(),
    ) as usize;
    let data_len = u64::from_le_bytes(
        data_mem[DATA_LEN_FIELD..DATA_LEN_FIELD + 8]
            .try_into()
            .unwrap(),
    ) as usize;
    // 防御性上限：Config.Cipher 的 key blob 恒为百字节级，
    // 超过 4096 视为读到了无关内存，直接拒绝。
    const MAX_BLOB_SIZE: usize = 4096;
    if data_ptr == 0 || data_len == 0 || data_len > MAX_BLOB_SIZE {
        return Vec::new();
    }
    // 实际读取截断到 1024 字节：XOR 掩码与 hex 字面量都只出现在
    // blob 头部，无需读全，控制读取量（data_len 可能虚报）。
    const READ_CAP: usize = 1024;
    let blob = match read_remote(handle, data_ptr, data_len.min(READ_CAP)) {
        Some(b) => b,
        None => return Vec::new(),
    };
    // 用掩码对 blob 做 XOR 解码。
    let decoded: Vec<u8> = blob
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ WINDOWS_CONFIG_XOR_MASK[i % WINDOWS_CONFIG_XOR_MASK.len()])
        .collect();
    // 从解码后的数据中找 x'<96hex>' 字面量格式（64 key hex + 32 salt hex）。
    if let Some(hex_str) = extract_hex_literal(&decoded) {
        // hex 是 96 位（64 key + 32 salt），取前 64 位作为 key。
        if hex_str.len() >= KEY_LEN * 2 {
            let key_hex = &hex_str[..KEY_LEN * 2];
            if let Ok(cand) = crypto::from_hex(key_hex) {
                return vec![cand];
            }
        }
    }
    Vec::new()
}

/// 从解码后数据中提取 `x'<hex>'` 格式字面量，返回 hex 字符串。
fn extract_hex_literal(data: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(data).ok()?;
    // 找 x'...' 或 X'...' 模式。
    let mut start = 0;
    while let Some(pos) = s[start..].find(|c: char| c == 'x' || c == 'X') {
        let abs = start + pos;
        if abs + 2 < s.len() && s.as_bytes()[abs + 1] == b'\'' {
            let after = &s[abs + 2..];
            if let Some(end) = after.find('\'') {
                let hex = &after[..end];
                if hex.len() >= KEY_LEN * 2 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Some(hex.to_string());
                }
            }
        }
        start = abs + 1;
    }
    None
}

fn scan_process(pid: u32, deadline: Instant) -> Result<Option<Vec<Key>>> {
    // 只依赖进程内存，不需要账号数据；返回所有唯一候选 key，由 run_capture_keys 做逐库匹配。
    let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        warn(323, &[&pid.to_string()]);
        return Ok(None);
    }
    let _handle = HandleGuard(handle);

    // 1. 找所有 CIPHER_CONFIG_NAME 字符串地址。
    let needle_addrs: Vec<u64> = scan_regions(handle, deadline, |hay, hay_addr| {
        find_hits(hay, hay_addr, CIPHER_CONFIG_NAME)
            .into_iter()
            .map(|hit| hit as u64)
            .collect()
    })?;
    if needle_addrs.is_empty() {
        return Ok(None);
    }

    // 2. 构造 pair patterns 并搜索引用。
    let patterns: Vec<Vec<u8>> = needle_addrs
        .into_iter()
        .map(|addr| pair_pattern(addr, CIPHER_CONFIG_NAME.len() as u64))
        .collect();
    let ref_addrs: Vec<usize> = scan_regions(handle, deadline, |hay, hay_addr| {
        patterns
            .iter()
            .flat_map(|pat| find_hits(hay, hay_addr, pat))
            .collect()
    })?;

    // 3. 从 blob 提取唯一候选 key。
    let mut unique: HashSet<Key> = HashSet::new();
    for ref_addr in ref_addrs {
        for blob in read_config_keys(handle, ref_addr) {
            if blob.len() == KEY_LEN {
                let mut cand = [0u8; KEY_LEN];
                cand.copy_from_slice(&blob);
                unique.insert(cand);
            }
        }
    }
    if unique.is_empty() {
        return Ok(None);
    }
    Ok(Some(unique.into_iter().collect()))
}

/// 完整 Windows 捕获流程：返回每库 key 映射（db 路径 → 64 位 hex key）。
/// Windows 4.1.12+ 起微信在内存中以每库独立 key（Config.Cipher blob）存储，
/// 不再存在单一 passphrase；故返回映射而非单字符串。
pub(crate) fn run_capture_keys(data: &AccountData, timeout: Duration) -> Result<Vec<DbKeyEntry>> {
    say(320);
    let pids = find_wechat_pids()?;
    ensure!(!pids.is_empty(), fail(-301));
    sayf(321, &[&pids.len().to_string()]);
    let deadline = Instant::now() + timeout;

    // 收集所有进程的全部唯一候选 key。
    let mut all_keys: Vec<Key> = Vec::new();
    for pid in pids {
        sayf(322, &[&pid.to_string()]);
        if let Some(keys) = scan_process(pid, deadline)? {
            all_keys.extend(keys);
        }
    }
    // 去重。
    let uniq: HashSet<Key> = all_keys.iter().copied().collect();
    let keys: Vec<Key> = uniq.into_iter().collect();
    if keys.is_empty() {
        return Err(fail(-302));
    }

    // 一次读取各库首页，供逐库匹配与主密钥探测复用（避免重复读库）。
    let pages: Vec<(PathBuf, Vec<u8>)> = data
        .encrypted_dbs
        .iter()
        .filter_map(|db| crate::shared::read_page1(db).map(|p| (db.clone(), p)))
        .collect();

    let keys = &keys;
    let out = parallel_chunks(&pages, |chunk| {
        chunk
            .iter()
            .filter_map(|(db, page1)| {
                keys.iter()
                    .find(|k| crypto::verify_page1(k, page1))
                    .map(|k| (db.clone(), crypto::to_hex(k)))
            })
            .collect()
    })?;
    // 任一库未匹配 → 视为整体失败（防漏解）。
    if out.len() != data.encrypted_dbs.len() {
        return Err(fail(-302));
    }

    // 主密钥探测：若存在单一 key 能通过全部库的全量校验（含派生形态），
    // 说明该版本仍保留主密钥 passphrase，返回单 key 映射。
    for k in keys {
        let pass_all = pages.iter().all(|(_, p)| crypto::verify_page1(k, p));
        if pass_all {
            // 主密钥存在：所有库映射到同一 key（单 passphrase 语义）。
            return Ok(pages
                .iter()
                .map(|(p, _)| (p.clone(), crypto::to_hex(k)))
                .collect());
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// 平台统一入口
// ---------------------------------------------------------------------------

/// 平台统一入口：完整 Windows 捕获流程，返回统一结果。
pub fn capture(_app: &Path, data: &AccountData, timeout: Duration) -> Result<CaptureResult> {
    let keys = run_capture_keys(data, timeout)?;
    let passphrase = keys[0].1.clone();
    // 主密钥探测：全库同 key（win.rs 已返回全同映射）时存在单一 passphrase；
    // 否则为每库独立 key 模式，JSON 输出 passphrase 置 null。
    let has_single_master = keys.iter().all(|(_, k)| k == &passphrase);
    Ok(CaptureResult {
        passphrase,
        key_map: Some(keys),
        has_single_master,
    })
}

/// Windows 每库 key 映射文件路径（`--output` 同目录，扩展名 keys.json）。
pub fn keys_path(output: &Path) -> Option<PathBuf> {
    Some(output.with_extension("keys.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_hits_lists_all_positions() {
        let hay = b"xxABCxxABCx";
        let hits = find_hits(hay, 0x1000, b"ABC");
        assert_eq!(hits, vec![0x1000 + 2, 0x1000 + 7]);
    }

    #[test]
    fn find_hits_overlapping_matches_not_missed() {
        let hits = find_hits(b"aaaaa", 0, b"aaa");
        assert_eq!(hits, vec![0, 1, 2]);
    }

    #[test]
    fn find_hits_handles_short_hay_and_empty_needle() {
        assert!(find_hits(b"", 0, b"x").is_empty());
        assert!(find_hits(b"ab", 0, b"abc").is_empty());
        assert!(find_hits(b"abc", 0, b"").is_empty());
    }

    #[test]
    fn pair_pattern_16_bytes() {
        let pat = pair_pattern(0x12345678, 0x20);
        assert_eq!(pat.len(), 16);
        assert_eq!(pat[..8], 0x12345678u64.to_le_bytes());
        assert_eq!(pat[8..], 0x20u64.to_le_bytes());
    }

    #[test]
    fn extract_hex_literal_works() {
        let data = b"foo x'abc123' bar";
        assert_eq!(extract_hex_literal(data), None); // 小于 64 hex
        let long_hex = "a".repeat(64);
        let data = format!("x'{long_hex}'").into_bytes();
        assert_eq!(
            extract_hex_literal(&data).as_deref(),
            Some(long_hex.as_str())
        );
    }

    #[test]
    fn extract_hex_literal_no_match() {
        assert!(extract_hex_literal(b"no hex here").is_none());
        assert!(extract_hex_literal(b"x''").is_none());
    }
}
