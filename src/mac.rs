//! macOS（Apple Silicon）捕获流程：对官方微信做事务性临时重签，
//! 再以 LLDB 软件断点挂在系统 `CCKeyDerivationPBKDF` 符号上，
//! 在用户登录触发派生时捕获数据库主密钥。

use anyhow::{ensure, Result};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::crypto::{self, KEY_LEN, SALT_LEN};
use crate::messages::*;
use crate::shared::{read_page1, set_mode, verify_all, AccountData, CaptureResult, IoCoded};

/// 微信安装路径（默认）。
pub const WECHAT_APP: &str = "/Applications/WeChat.app";
const TENCENT_TEAM_ID: &str = "5A4RE8SF68";
const BUNDLE_ID: &str = "com.tencent.xinWeChat";
/// 固定备份位置，Ctrl-C 处理器无需上下文即可执行恢复。
const BACKUP_DIR: &str = ".wcdb-key/backup";

/// 返回 macOS 微信数据根目录（xwechat_files）。
pub fn default_db_root() -> Option<PathBuf> {
    Some(
        crate::shared::home_dir()
            .ok()?
            .join("Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files"),
    )
}

// ---------------------------------------------------------------------------
// 进程辅助
// ---------------------------------------------------------------------------

fn sh(program: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .coded()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    ensure!(
        out.status.success(),
        failf(
            -500,
            &[
                &format!("{program} {}", args.join(" ")),
                &out.status.to_string(),
                text.trim(),
            ]
        )
    );
    Ok(text)
}

fn wait_until<F: Fn() -> bool>(timeout: Duration, interval: Duration, cond: F) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if cond() {
            return true;
        }
        std::thread::sleep(interval);
    }
    cond()
}

fn wechat_pid() -> Option<u32> {
    let out = Command::new("pgrep").args(["-x", "WeChat"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    // 多行输出时取第一个 trim 后非空且可解析的 PID。
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.trim().parse().ok())
}

fn kill_wechat() -> Result<()> {
    if wechat_pid().is_none() {
        return Ok(());
    }
    let _ = Command::new("pkill").args(["-x", "WeChat"]).status();
    ensure!(
        wait_until(Duration::from_secs(10), Duration::from_millis(300), || {
            wechat_pid().is_none()
        }),
        fail(-200)
    );
    Ok(())
}

/// 直接 exec 微信主二进制。4.1.13 起 LaunchServices 会拒绝重签后的
/// `open`（LSOpen -128），直接执行可执行文件不受影响。
fn launch(app: &Path) -> Result<()> {
    Command::new(app.join("Contents/MacOS/WeChat"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .coded()?;
    ensure!(
        wait_until(Duration::from_secs(30), Duration::from_millis(300), || {
            wechat_pid().is_some()
        }),
        fail(-201)
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 官方签名校验
// ---------------------------------------------------------------------------

/// 校验微信为腾讯 Developer ID 正式签名、深度签名有效且身份匹配。
fn is_officially_signed(app: &Path) -> Result<bool> {
    if sh(
        "codesign",
        &["--verify", "--deep", "--strict", &app.to_string_lossy()],
    )
    .is_err()
    {
        return Ok(false);
    }
    let details = sh("codesign", &["-dv", "--verbose=4", &app.to_string_lossy()])?;
    Ok(
        details.contains(&format!("TeamIdentifier={TENCENT_TEAM_ID}"))
            && details.contains(&format!("Identifier={BUNDLE_ID}")),
    )
}

fn require_official(app: &Path) -> Result<()> {
    ensure!(app.is_dir(), failf(-100, &[&app.display().to_string()]));
    ensure!(
        is_officially_signed(app)?,
        failf(-101, &[&app.display().to_string()])
    );
    Ok(())
}

fn wechat_version(app: &Path) -> String {
    sh(
        "plutil",
        &[
            "-extract",
            "CFBundleShortVersionString",
            "raw",
            &app.join("Contents/Info.plist").to_string_lossy(),
        ],
    )
    .map(|s| s.trim().to_string())
    .unwrap_or_default()
}

fn require_lldb() -> Result<()> {
    if sh("which", &["lldb"]).is_err() {
        return Err(failf(-23, &["lldb"]));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 事务性备份 / 重签 / 恢复
// ---------------------------------------------------------------------------

fn backup_dir() -> Result<PathBuf> {
    Ok(crate::shared::home_dir()?.join(BACKUP_DIR))
}

/// 以 APFS 克隆（写时复制，瞬时完成且不占额外空间）备份官方微信。
/// 返回备份根目录，微信包位于 `<root>/WeChat.app`。
fn backup(app: &Path) -> Result<PathBuf> {
    let root = backup_dir()?;
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).coded()?;
    set_mode(&root, 0o700)?;
    sh(
        "cp",
        &["-cR", &app.to_string_lossy(), &root.to_string_lossy()],
    )?;
    ensure!(is_officially_signed(&root.join("WeChat.app"))?, fail(-202));
    Ok(root)
}

/// 结束微信进程，再将备份以“暂存克隆 + 三段式原子交换”还原到 `app`：
/// 新版本先以临时名就位（与 `app` 同文件系统，rename 原子），
/// 删除旧版后一步 rename 到位，非原子窗口仅剩 `remove_dir_all` 本身。
/// 任一步失败都保证：旧版仍可用、或新版本以临时名/暂存目录保留供手动恢复。
fn restore_to(app: &Path, backup: &Path) -> Result<()> {
    let _ = kill_wechat();
    let parent = app.parent().unwrap_or(Path::new("/"));
    let staged = parent.join(".wcdb-key-restore-tmp");
    let staged_app = staged.join("WeChat.app");
    // 新版本就位的临时名：与 app 同目录（同文件系统），隐藏名避免与真实包冲突。
    let pending = parent.join(".wcdb-key-restore-tmp.app");
    let _ = std::fs::remove_dir_all(&staged);
    let _ = std::fs::remove_dir_all(&pending);
    std::fs::create_dir_all(&staged).coded()?;
    set_mode(&staged, 0o700)?;
    sh(
        "cp",
        &[
            "-cR",
            &backup.join("WeChat.app").to_string_lossy(),
            &staged_app.to_string_lossy(),
        ],
    )?;
    // 1) 新版本先就位（临时名）。失败则 app 未动、staged 保留官方版。
    std::fs::rename(&staged_app, &pending).map_err(|_| fail(-205))?;
    // 2) 删除旧版。失败时尽力把新版本归还 staged 供手动恢复。
    if let Err(e) = std::fs::remove_dir_all(app) {
        let _ = std::fs::rename(&pending, &staged_app);
        return Err(failf(-204, &[&e.to_string()]));
    }
    // 3) 原子交换。失败则新版本已就位于 pending，保留供手动恢复。
    if std::fs::rename(&pending, app).is_err() {
        return Err(fail(-205));
    }
    let _ = std::fs::remove_dir_all(&staged);
    require_official(app)?;
    Ok(())
}

/// 校验备份存在且为官方签名，返回备份根目录。
fn validated_backup() -> Result<PathBuf> {
    let backup = backup_dir()?;
    let bundle = backup.join("WeChat.app");
    ensure!(
        bundle.is_dir(),
        failf(-207, &[&backup.display().to_string()])
    );
    ensure!(
        is_officially_signed(&bundle)?,
        failf(-208, &[&backup.display().to_string()])
    );
    Ok(backup)
}

/// 上次运行可能在重签后中断，先于任何操作前从备份恢复。
fn recover_stale_state(app: &Path) -> Result<()> {
    if is_officially_signed(app)? {
        return Ok(());
    }
    let backup = validated_backup()?;
    warn(209, &[]);
    restore_to(app, &backup)
}

/// 独立 `restore` 命令：从备份恢复官方微信。
pub fn restore_and_report(app: &Path) -> Result<()> {
    let backup = validated_backup()?;
    restore_to(app, &backup)?;
    if crate::messages::json_mode() {
        println!(
            "{}",
            crate::messages::json_output(1, serde_json::Value::Null)
        );
    } else {
        sayf(208, &[&backup.display().to_string()]);
    }
    Ok(())
}

/// 事务性封装：为捕获临时重签官方微信，结束时总是恢复。
///
/// begin()：结束微信 → 校验官方签名 → APFS 克隆备份 → 重签。
/// Drop：若 finish() 未被调用，自动恢复官方微信。
pub(crate) struct Transaction {
    app: PathBuf,
    backup: PathBuf,
    finished: bool,
}

impl Transaction {
    fn begin(app: &Path) -> Result<Self> {
        recover_stale_state(app)?;
        kill_wechat()?;
        let backup = backup(app)?;
        // sh() 失败时已返回编号 -500 的错误，附带完整细节。
        sh(
            "codesign",
            &["--force", "--deep", "--sign", "-", &app.to_string_lossy()],
        )?;
        let _ = ACTIVE.set((app.to_path_buf(), backup.to_path_buf()));
        Ok(Transaction {
            app: app.to_path_buf(),
            backup,
            finished: false,
        })
    }

    fn finish(mut self) -> Result<()> {
        self.finished = true; // 避免 Drop 重复执行恢复。
        restore_to(&self.app, &self.backup)
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        warn(210, &[]);
        if let Err(e) = restore_to(&self.app, &self.backup) {
            warn(
                -216,
                &[&format!("{e:#}"), &self.backup.display().to_string()],
            );
        } else {
            warn(208, &[&self.backup.display().to_string()]);
        }
    }
}

/// 记录当前事务的路径，Ctrl-C 处理器据此恢复实际被修改的
/// 微信（支持自定义 --wechat-path）。
static ACTIVE: OnceLock<(PathBuf, PathBuf)> = OnceLock::new();

fn install_ctrlc_restore() {
    let _ = ctrlc::set_handler(|| {
        if let Some((app, backup)) = ACTIVE.get() {
            warn(210, &[]);
            let _ = restore_to(app, backup);
        }
        std::process::exit(130);
    });
}

// ---------------------------------------------------------------------------
// LLDB 监测
// ---------------------------------------------------------------------------

/// LLDB 内嵌 Python 回调脚本（编译期从 `hook.py` 嵌入，
/// 独立文件便于编辑与版本管理）。在系统公开符号
/// `CCKeyDerivationPBKDF` 上放置软件断点，按微信的参数形状
/// （algorithm=2、len=32/16、prf=5、rounds=256000）与账号数据库 salt
/// 过滤调用，候选通过探测库 page-1 HMAC 校验后写回结果并终止临时进程。
const CALLBACK_TEMPLATE: &str = include_str!("hook.py");

fn lldb_command_file(pid: u32, callback: &Path) -> String {
    format!(
        "settings set target.preload-symbols false\n\
         process attach -p {pid}\n\
         process handle SIGTRAP -n false -p false -s false\n\
         command script import {}\n\
         process continue\n\
         quit\n",
        callback.to_string_lossy()
    )
}

/// 已附加到微信的 `lldb` 进程。Drop 时结束调试器并删除临时目录，
/// 保证所有提前返回路径都会清理（失败保留诊断文件除外）。
struct Monitor {
    tmp_dir: PathBuf,
    result_path: PathBuf,
    log_path: PathBuf,
    child: Child,
    /// 失败时保留临时目录（lldb.log / result.json 供排错），成功则清理。
    retain_logs: bool,
}

impl Monitor {
    fn start(pid: u32, salts: &[String], probe_page1: &[u8]) -> Result<Self> {
        let tmp_dir = std::env::temp_dir().join(format!("wcdb-key-{}", std::process::id()));
        std::fs::create_dir_all(&tmp_dir).coded()?;
        set_mode(&tmp_dir, 0o700)?;

        let result_path = tmp_dir.join("result.json");
        std::fs::File::create(&result_path).coded()?;
        set_mode(&result_path, 0o600)?;

        let callback = tmp_dir.join("hook.py");
        let script = CALLBACK_TEMPLATE
            .replace("@RESULT_PATH@", &result_path.to_string_lossy())
            .replace(
                "@SALTS@",
                &serde_json::to_string(salts).map_err(|e| fail_io(-507, e))?,
            )
            .replace("@PAGE1@", &crypto::to_hex(probe_page1));
        std::fs::write(&callback, script).coded()?;

        let cmd_file = tmp_dir.join("capture.lldb");
        std::fs::write(&cmd_file, lldb_command_file(pid, &callback)).coded()?;

        let log_path = tmp_dir.join("lldb.log");
        let log = std::fs::File::create(&log_path).coded()?;
        let child = Command::new("lldb")
            .args(["-b", "-s", &cmd_file.to_string_lossy()])
            .stdin(Stdio::null())
            .stdout(log.try_clone().coded()?)
            .stderr(log)
            .spawn()
            .map_err(|e| failf(-217, &[&e.to_string()]))?;

        Ok(Monitor {
            tmp_dir,
            result_path,
            log_path,
            child,
            retain_logs: false,
        })
    }

    fn log_tail(&self) -> String {
        let s = match std::fs::read_to_string(&self.log_path) {
            Ok(s) => s,
            _ => return String::new(),
        };
        let lines: Vec<&str> = s.lines().collect();
        let start = lines.len().saturating_sub(15);
        lines[start..].join("\n")
    }

    /// 附加失败或断点未解析时快速失败。
    fn wait_ready(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = self.child.try_wait().coded()? {
                return Err(failf(-210, &[&status.to_string(), &self.log_tail()]));
            }
            let log = std::fs::read_to_string(&self.log_path).unwrap_or_default();
            if log.contains("attach failed") || log.contains("not allowed to attach") {
                return Err(failf(-209, &[&self.log_tail()]));
            }
            if let Some(rest) = log.split("WCDB_KEY_MONITOR_READY").nth(1) {
                let locations = rest
                    .split_whitespace()
                    .next()
                    .and_then(|n| n.parse().ok())
                    .unwrap_or(0);
                ensure!(locations > 0, fail(-211));
                return Ok(());
            }
            ensure!(Instant::now() < deadline, failf(-212, &[&self.log_tail()]));
            std::thread::sleep(Duration::from_millis(300));
        }
    }

    /// 轮询捕获结果，返回 64 位十六进制 passphrase。
    fn wait_passphrase(&mut self, timeout: Duration) -> Result<String> {
        let deadline = Instant::now() + timeout;
        loop {
            let text = std::fs::read_to_string(&self.result_path).unwrap_or_default();
            if let Some(status) = self.child.try_wait().coded()? {
                if let Some(pass) = extract_passphrase(&text) {
                    return Ok(pass);
                }
                return Err(failf(-215, &[&status.to_string(), &self.log_tail()]));
            }
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
                if let Some(err) = value.get("error").and_then(|e| e.as_str()) {
                    return Err(failf(-214, &[err]));
                }
            }
            if let Some(pass) = extract_passphrase(&text) {
                return Ok(pass);
            }
            ensure!(
                Instant::now() < deadline,
                failf(-213, &[&timeout.as_secs().to_string()])
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // 失败时保留临时目录（lldb.log / result.json）供排错，成功则清理。
        if !self.retain_logs {
            let _ = std::fs::remove_dir_all(&self.tmp_dir);
        }
    }
}

fn extract_passphrase(json_text: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(json_text).ok()?;
    let pass = value.get("passphrase")?.as_str()?;
    (pass.len() == KEY_LEN * 2).then(|| pass.to_string())
}

// ---------------------------------------------------------------------------
// 平台入口
// ---------------------------------------------------------------------------

/// 完整 macOS 捕获流程，成功时返回 64 位十六进制 passphrase。
pub(crate) fn run_capture(app: &Path, data: &AccountData, timeout: Duration) -> Result<String> {
    require_lldb()?;
    require_official(app)?;
    sayf(202, &[&wechat_version(app), &app.display().to_string()]);

    say(203);
    install_ctrlc_restore();
    let transaction = Transaction::begin(app)?;

    launch(app)?;
    let pid = wechat_pid().ok_or_else(|| fail(-218))?;
    // LLDB 回调按各数据库自身的 salt 过滤 PBKDF 调用。
    let salts: Vec<String> = data
        .encrypted_dbs
        .iter()
        .filter_map(|db| read_page1(db).map(|p| crypto::to_hex(&p[..SALT_LEN])))
        .collect();
    ensure!(!salts.is_empty(), fail(-219));
    let mut monitor = Monitor::start(pid, &salts, &data.probe_page1)?;
    let result = (|| -> Result<String> {
        monitor.wait_ready()?;
        sayf(205, &[&pid.to_string()]);
        say(206);
        let pass = monitor.wait_passphrase(timeout)?;
        say(207);
        transaction.finish()?;
        sayf(208, &[&backup_dir()?.display().to_string()]);
        Ok(pass)
    })();
    // 失败时保留临时目录（lldb.log / result.json）供排错并提示路径。
    if result.is_err() {
        monitor.retain_logs = true;
        sayf(211, &[&monitor.tmp_dir.display().to_string()]);
    }
    drop(monitor); // 结束调试器；成功则删除临时目录。
    result
}

// ---------------------------------------------------------------------------
// 平台统一入口
// ---------------------------------------------------------------------------

/// 平台统一入口：完整 macOS 捕获流程 + 全库校验，返回统一结果。
pub fn capture(app: &Path, data: &AccountData, timeout: Duration) -> Result<CaptureResult> {
    let passphrase = run_capture(app, data, timeout)?;
    verify_all(data, &passphrase)?;
    Ok(CaptureResult {
        passphrase,
        key_map: None,
        has_single_master: true,
    })
}

/// macOS 为单一主密钥模式，无每库 keys.json。
pub fn keys_path(_output: &Path) -> Option<PathBuf> {
    None
}
