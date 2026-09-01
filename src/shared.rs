//! 跨平台：账号发现、数据库扫描与密钥校验。
//! 平台专属捕获逻辑见 `mac.rs` / `win.rs`。

use anyhow::{ensure, Result};
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::crypto::PAGE_SIZE;
use crate::messages::*;

/// 为 `std::io::Result` 补充编号化错误转换（-501）。
pub(crate) trait IoCoded<T> {
    fn coded(self) -> Result<T>;
}
impl<T> IoCoded<T> for std::io::Result<T> {
    fn coded(self) -> Result<T> {
        self.map_err(|e| fail_io(-501, e))
    }
}
/// 平台捕获统一结果：主密钥 + 每库 key 映射 + 是否单一主密钥。
/// 各平台模块 `capture()` 返回此类型，main.rs 统一组装输出。
pub(crate) struct CaptureResult {
    /// 主密钥（64 位 hex）。无单一主密钥时为第一库 key。
    pub passphrase: String,
    /// 每库 key 映射（Windows 独立 key 模式）；macOS 为 None。
    pub key_map: Option<Vec<(PathBuf, String)>>,
    /// 是否存在单一主密钥（macOS 恒有；Windows 主密钥探测通过时也有）。
    pub has_single_master: bool,
}

// ---------------------------------------------------------------------------
// 账号发现与数据库扫描
// ---------------------------------------------------------------------------

fn collect_dbs(dir: &Path, out: &mut Vec<PathBuf>) {
    // 跳过不可读目录符合容错设计（数据目录可能含权限异常文件），不传播错误。
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_dir() {
            collect_dbs(&path, out);
        } else if path.extension().is_some_and(|e| e == "db") && read_page1(&path).is_some() {
            out.push(path);
        }
    }
}

pub(crate) fn read_page1(db: &Path) -> Option<Vec<u8>> {
    // 只读首页 4096 字节：真实 message_0.db 可达数百 MB，整库读入浪费 IO 与内存。
    let mut buf = Vec::with_capacity(PAGE_SIZE);
    std::fs::File::open(db)
        .ok()?
        .take(PAGE_SIZE as u64)
        .read_to_end(&mut buf)
        .ok()?;
    (buf.len() == PAGE_SIZE && !buf.starts_with(b"SQLite format 3")).then_some(buf)
}

/// 用户主目录（HOME，Windows 回退到 USERPROFILE）。
pub(crate) fn home_dir() -> Result<PathBuf> {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .map_err(|_| fail(-502))
}

/// 账号数据：探测首页与全部加密数据库路径。
#[derive(Debug)]
pub struct AccountData {
    /// 探测数据库的首页（HMAC 校验基准，仅 macOS 捕获需要）。
    #[cfg(target_os = "macos")]
    pub probe_page1: Vec<u8>,
    /// 全部加密数据库，捕获后逐一校验。
    pub encrypted_dbs: Vec<PathBuf>,
}

/// 收集账号数据目录下的全部加密数据库与探测首页。
pub fn collect_account_data(db_dir: &Path) -> Result<AccountData> {
    let mut encrypted_dbs = Vec::new();
    collect_dbs(db_dir, &mut encrypted_dbs);
    ensure!(!encrypted_dbs.is_empty(), fail(-103));

    #[cfg(target_os = "macos")]
    let probe_page1 = {
        encrypted_dbs
            .iter()
            .find(|p| p.file_name().is_some_and(|n| n == "message_0.db"))
            .or_else(|| encrypted_dbs.first())
            .and_then(|p| read_page1(p))
            .ok_or_else(|| fail(-104))?
    };

    Ok(AccountData {
        #[cfg(target_os = "macos")]
        probe_page1,
        encrypted_dbs,
    })
}

/// 在平台数据根目录下发现账号目录，按最近使用排序。
pub fn list_accounts(root: &Path) -> Result<Vec<PathBuf>> {
    ensure!(root.is_dir(), failf(-102, &[&root.display().to_string()]));
    let mut dirs: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(root)
        .coded()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.join("db_storage").is_dir())
        .filter_map(|p| Some((p.join("db_storage").metadata().ok()?.modified().ok()?, p)))
        .collect();
    dirs.sort_by_key(|(t, _)| std::cmp::Reverse(*t));
    ensure!(!dirs.is_empty(), fail(-107));
    Ok(dirs.into_iter().map(|(_, p)| p).collect())
}

// ---------------------------------------------------------------------------
// 校验
// ---------------------------------------------------------------------------

/// 用捕获到的 passphrase 校验账号下全部加密数据库。
/// 全有或全无：任一数据库校验失败即整体拒绝。
/// 按核数并行执行（每库需两次 256000 轮 PBKDF2，串行耗时显著）。
/// 仅 macOS 主密钥模式使用（Windows 为每库独立 key，校验在 win.rs 内完成）。
#[cfg(target_os = "macos")]
pub fn verify_all(data: &AccountData, passphrase_hex: &str) -> Result<()> {
    let passphrase = crate::crypto::from_hex(passphrase_hex)?
        .try_into()
        .map_err(|_| fail(-106))?;
    let failed = parallel_chunks(&data.encrypted_dbs, |group| {
        group
            .iter()
            .filter(|db| {
                // is_none_or 稳定于 Rust 1.82，MSRV 以此为界。
                read_page1(db).is_none_or(|p| !crate::crypto::verify_page1(&passphrase, &p))
            })
            .cloned()
            .collect()
    })?;
    ensure!(
        failed.is_empty(),
        failf(
            -105,
            &[&failed.len().to_string(), &failed[0].display().to_string()]
        )
    );
    Ok(())
}

/// 按核数分块并行执行 `f`，聚合各块结果；任一工作线程异常视为整体失败。
/// 校验类业务（verify_all / run_capture_keys）共用，避免并行骨架重复。
pub(crate) fn parallel_chunks<T, U, F>(items: &[T], f: F) -> Result<Vec<U>>
where
    T: Sync,
    U: Send,
    F: Fn(&[T]) -> Vec<U> + Sync,
{
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(1, items.len().max(1));
    let chunk = items.len().div_ceil(workers).max(1);
    let f = &f;
    std::thread::scope(|s| -> Result<Vec<U>> {
        let handles: Vec<_> = items
            .chunks(chunk)
            .map(|group| s.spawn(move || f(group)))
            .collect();
        let mut out = Vec::new();
        for h in handles {
            match h.join() {
                Ok(v) => out.extend(v),
                Err(_) => return Err(fail(-1)),
            }
        }
        Ok(out)
    })
}

/// 设置受限文件权限（Unix）。Windows 下为空操作——
/// 用户主目录下的文件本身已仅当前用户可见。
pub fn set_mode(path: impl AsRef<Path>, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).coded()?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

/// 对真实账号的端到端校验与合成库单测（真实数据经环境变量传入，不入库）：
///   WCDB_TEST_DB_DIR=.../xwechat_files/<account>/db_storage \
///   WCDB_TEST_PASSPHRASE=<64 hex chars> cargo test -- --ignored
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{synth, KEY_LEN};
    use crate::messages::WxError;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("wcdb-key-test-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("db_storage")).unwrap();
        dir
    }

    fn write_file(db_dir: &Path, name: &str, data: &[u8]) {
        let path = db_dir.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, data).unwrap();
    }

    fn write_db(db_dir: &Path, name: &str, passphrase: &[u8; KEY_LEN], salt: [u8; 16]) {
        write_file(db_dir, name, &synth::page1(passphrase, salt));
    }

    #[test]
    fn collect_skips_plaintext_and_prefers_message0() {
        let dir = temp_dir("collect");
        let good = [7u8; KEY_LEN];
        write_db(&dir, "db_storage/message/message_0.db", &good, [1u8; 16]);
        write_db(&dir, "db_storage/session/session.db", &good, [2u8; 16]);
        write_file(&dir, "db_storage/plain/plain.db", b"SQLite format 3xxxx");

        let data = collect_account_data(&dir.join("db_storage")).unwrap();
        assert_eq!(data.encrypted_dbs.len(), 2);
        assert!(data
            .encrypted_dbs
            .iter()
            .all(|p| p.file_name().is_some_and(|n| n != "plain.db")));
        // 探测库优先取 message_0.db。
        #[cfg(target_os = "macos")]
        assert!(data.probe_page1[..16].starts_with(&[1u8, 1]));
    }

    #[test]
    fn collect_empty_dir_fails() {
        let dir = temp_dir("empty");
        let err = collect_account_data(&dir.join("db_storage")).unwrap_err();
        assert_eq!(err.downcast_ref::<WxError>().unwrap().code, -103);
    }

    #[test]
    fn read_page1_reads_only_head_of_large_db() {
        let dir = temp_dir("large");
        // 10MB+ 假库：只应读到首页 4096 字节。
        let big = vec![0u8; 10 * 1024 * 1024];
        let path = dir.join("db_storage/message/large.db");
        write_file(&dir, "db_storage/message/large.db", &big);
        assert_eq!(read_page1(&path).unwrap(), big[..PAGE_SIZE].to_vec());
        // 不足一页仍返回 None（语义与原 std::fs::read 一致）。
        write_file(&dir, "db_storage/message/large.db", &big[..100]);
        assert!(read_page1(&path).is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn verify_all_passes_and_fails_as_whole() {
        let dir = temp_dir("verify");
        let passphrase = [7u8; KEY_LEN];
        write_db(
            &dir,
            "db_storage/message/message_0.db",
            &passphrase,
            [1u8; 16],
        );
        write_db(
            &dir,
            "db_storage/session/session.db",
            &passphrase,
            [2u8; 16],
        );
        let data = collect_account_data(&dir.join("db_storage")).unwrap();

        // 正确密钥：全库通过。
        verify_all(&data, &crate::crypto::to_hex(&passphrase)).unwrap();

        // 错误密钥：任一库失败即整体拒绝。
        let err = verify_all(&data, &crate::crypto::to_hex(&[8u8; KEY_LEN])).unwrap_err();
        assert_eq!(err.downcast_ref::<WxError>().unwrap().code, -105);
    }

    // 真实账号端到端（数据经环境变量传入，不入库）：
    //   WCDB_TEST_DB_DIR=.../xwechat_files/<account>/db_storage \
    //   WCDB_TEST_PASSPHRASE=<64 hex chars> cargo test -- --ignored
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires WCDB_TEST_DB_DIR + WCDB_TEST_PASSPHRASE env"]
    fn verify_real_account() {
        let db_dir = PathBuf::from(std::env::var("WCDB_TEST_DB_DIR").expect("WCDB_TEST_DB_DIR"));
        let pass = std::env::var("WCDB_TEST_PASSPHRASE").expect("WCDB_TEST_PASSPHRASE");
        let data = collect_account_data(&db_dir).expect("collect");
        eprintln!("encrypted databases: {}", data.encrypted_dbs.len());
        verify_all(&data, &pass).expect("verify_all");
    }
}
