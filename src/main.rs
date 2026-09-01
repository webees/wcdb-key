//! wcdb-key — 提取微信 4.x 的 WCDB 数据库主密钥。
//!   macOS（Apple Silicon）：事务性重签 + LLDB 软件断点。
//!   Windows：对运行中的微信进程做内存特征扫描。
//! 纯本地运行，无网络请求。所有输出带数字编号（见 messages.rs）：
//! 编号 > 0 为成功/信息，< 0 为错误。

mod crypto;
mod messages;
mod shared;

#[cfg(target_os = "macos")]
mod mac;
#[cfg(target_os = "macos")]
use mac as platform;

#[cfg(target_os = "windows")]
mod win;
#[cfg(target_os = "windows")]
use win as platform;

use anyhow::{ensure, Result};
use messages::*;
use shared::IoCoded;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

// 静态帮助文本（CODING.md §3 豁免）：排版类文档，含 {version}/{platform} 占位，
// 不走消息注册表；运行期用户可见文本仍一律入注册表。
const USAGE: &str = "\
wcdb-key {version} — 微信 4.x WCDB 主密钥提取（{platform}）

用法:
  wcdb-key capture [选项]    完整捕获流程
  wcdb-key restore           从备份恢复官方微信（仅 macOS）
  wcdb-key help              显示本帮助

通用选项:
  --db-dir <PATH>        指定账号数据目录（默认自动发现最近使用的账号）
  --timeout <SECONDS>    等待捕获的超时秒数（默认 900；Windows 为扫描预算）
  --output <PATH>        密钥保存路径（默认 ~/.wcdb-key/wechat-passphrase.json）
  --json                 机器可读输出：stdout 只输出结果 JSON，日志走 stderr
  -h, --help             显示本帮助
  -V, --version          显示版本号

macOS capture 附加选项:
  --wechat-path <PATH>   微信安装路径（默认 /Applications/WeChat.app）
";

struct Args {
    wechat_path: PathBuf,
    db_dir: Option<PathBuf>,
    timeout: Duration,
    output: Option<PathBuf>,
    json: bool,
}

fn platform_label() -> &'static str {
    if cfg!(target_os = "macos") {
        "macOS Apple Silicon"
    } else {
        "Windows x64"
    }
}

/// 输出文本：--json 模式下包装为编号 1 的结果 JSON，否则原样打印。
fn print_text(text: &str) {
    if messages::json_mode() {
        println!(
            "{}",
            messages::json_output_with(1, serde_json::Value::Null, text)
        );
    } else {
        println!("{text}");
    }
}

fn print_usage() {
    let text = USAGE
        .replace("{version}", env!("CARGO_PKG_VERSION"))
        .replace("{platform}", platform_label());
    print_text(&text);
}

fn print_version() {
    print_text(&format!("wcdb-key {}", env!("CARGO_PKG_VERSION")));
}

fn next_value(rest: &mut impl Iterator<Item = String>, flag: &str) -> Result<String> {
    rest.next().ok_or_else(|| failf(-12, &[flag]))
}

fn parse_args() -> Result<(String, Args)> {
    let mut args = std::env::args().skip(1);
    let Some(cmd) = args.next() else {
        print_usage();
        std::process::exit(2);
    };
    if matches!(cmd.as_str(), "help" | "-h" | "--help") {
        print_usage();
        std::process::exit(0);
    }
    if matches!(cmd.as_str(), "--version" | "-V") {
        print_version();
        std::process::exit(0);
    }
    ensure!(
        cmd == "capture" || (cmd == "restore" && cfg!(target_os = "macos")),
        failf(
            -10,
            &[
                &cmd,
                if cfg!(target_os = "macos") {
                    "capture | help | restore"
                } else {
                    "capture | help"
                }
            ]
        )
    );

    let mut parsed = Args {
        wechat_path: wechat_path_default(),
        db_dir: None,
        timeout: Duration::from_secs(900),
        output: None,
        json: false,
    };
    let mut rest = args;
    while let Some(flag) = rest.next() {
        match flag.as_str() {
            "--json" => {
                parsed.json = true;
                messages::set_json_mode(true);
            }
            "--wechat-path" => {
                if cfg!(target_os = "macos") {
                    parsed.wechat_path = PathBuf::from(next_value(&mut rest, &flag)?);
                } else {
                    return Err(failf(-25, &[&flag]));
                }
            }
            "--db-dir" => parsed.db_dir = Some(PathBuf::from(next_value(&mut rest, &flag)?)),
            "--output" => parsed.output = Some(PathBuf::from(next_value(&mut rest, &flag)?)),
            "--timeout" => {
                let secs: i64 = next_value(&mut rest, &flag)?
                    .parse()
                    .map_err(|_| fail(-13))?;
                ensure!(secs > 0, fail(-14));
                parsed.timeout = Duration::from_secs(secs as u64);
            }
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            "-V" | "--version" => {
                print_version();
                std::process::exit(0);
            }
            other => return Err(failf(-11, &[other])),
        }
    }
    Ok((cmd, parsed))
}

fn wechat_path_default() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from(platform::WECHAT_APP)
    }
    #[cfg(not(target_os = "macos"))]
    {
        PathBuf::new()
    }
}

/// 以 0700 目录 + 0600 文件、tmp→rename 原子方式落盘敏感 JSON。
/// 统一 create_dir_all → set_mode 700 → .tmp → set_mode 600 → write →
/// sync_all → rename 七步流程。
fn write_sensitive_json(output: &Path, json_str: &str) -> Result<PathBuf> {
    // `--output` 必须是文件路径：以分隔符结尾（`/dir/`）或指向已存在
    // 目录（`/dir`）都无文件名可落盘，拒绝以免误写。
    let path_str = output.to_string_lossy();
    if path_str.is_empty() || path_str.ends_with('/') || path_str.ends_with('\\') {
        return Err(fail(-26));
    }
    if output.is_dir() {
        return Err(fail(-26));
    }
    let dir = output.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir).coded()?;
    shared::set_mode(dir, 0o700)?;
    let name = output
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!("{name}.tmp"));
    {
        let mut f = std::fs::File::create(&tmp).coded()?;
        shared::set_mode(&tmp, 0o600)?;
        f.write_all(json_str.as_bytes()).coded()?;
        f.sync_all().coded()?;
    }
    std::fs::rename(&tmp, output).coded()?;
    Ok(output.to_path_buf())
}

fn default_output() -> Result<PathBuf> {
    Ok(shared::home_dir()?.join(".wcdb-key/wechat-passphrase.json"))
}

fn choose_account(db_dir: Option<PathBuf>) -> Result<PathBuf> {
    let root = match db_dir {
        Some(d) => {
            ensure!(d.is_dir(), failf(-16, &[&d.display().to_string()]));
            d
        }
        None => platform::default_db_root().ok_or_else(|| fail(-17))?,
    };
    // 同时接受 xwechat_files 根目录或账号目录两种形式。
    if root.join("db_storage").is_dir() {
        return Ok(root);
    }
    let accounts = shared::list_accounts(&root)?;
    if accounts.len() == 1 {
        return Ok(accounts[0].clone());
    }
    say(130);
    for (i, dir) in accounts.iter().enumerate() {
        sayf(132, &[&(i + 1).to_string(), &dir.display().to_string()]);
    }
    ask(131);
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).coded()?;
    let idx: usize = line.trim().parse().map_err(|_| fail(-15))?;
    ensure!((1..=accounts.len()).contains(&idx), fail(-15));
    Ok(accounts[idx - 1].clone())
}

fn capture(args: &Args) -> Result<()> {
    let account = choose_account(args.db_dir.clone())?;
    let db_dir = if account.join("db_storage").is_dir() {
        account.join("db_storage")
    } else {
        account.clone()
    };
    let data = shared::collect_account_data(&db_dir)?;
    let account_name = account
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    sayf(101, &[&account_name, &data.encrypted_dbs.len().to_string()]);

    // 平台差异收敛至 platform::capture / platform::keys_path。
    let output_path = match args.output.clone() {
        Some(p) => p,
        None => default_output()?,
    };
    let keys_path = platform::keys_path(&output_path);
    let result = platform::capture(&args.wechat_path, &data, args.timeout)?;
    sayf(141, &[&data.encrypted_dbs.len().to_string()]);

    // Windows 每库独立 key 模式：先落盘 keys.json 映射。
    if let (Some(ref p), Some(ref key_map)) = (&keys_path, &result.key_map) {
        let json_map: std::collections::BTreeMap<String, String> = key_map
            .iter()
            .map(|(db_path, k)| {
                (
                    db_path
                        .file_name()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_default(),
                    k.clone(),
                )
            })
            .collect();
        let json = serde_json::json!(&json_map).to_string();
        write_sensitive_json(p, &json)?;
    }

    let path = if result.has_single_master {
        let json = serde_json::json!({ "passphrase": &result.passphrase }).to_string();
        let p = write_sensitive_json(&output_path, &json)?;
        sayf(143, &[&p.display().to_string()]);
        p
    } else {
        // 无单一主密钥：不写单 key 文件，密钥见 keys.json 映射。
        output_path
    };

    if messages::json_mode() {
        print_json_output(&JsonOutput {
            has_single_master: result.has_single_master,
            passphrase: &result.passphrase,
            output_path: &path,
            keys_path: &keys_path,
            account_name: &account_name,
            db_count: data.encrypted_dbs.len(),
        });
    } else if let Some(ref p) = keys_path {
        if result.has_single_master {
            sayf(145, &[&result.passphrase, &p.display().to_string()]);
        } else {
            sayf(146, &[&p.display().to_string()]);
        }
    } else {
        sayf(144, &[&result.passphrase]);
    }
    Ok(())
}

/// --json 结果输出所需的上下文（聚合避免长参数列表）。
struct JsonOutput<'a> {
    has_single_master: bool,
    passphrase: &'a str,
    output_path: &'a Path,
    keys_path: &'a Option<PathBuf>,
    account_name: &'a str,
    db_count: usize,
}

/// 组装并打印 --json 模式下的结果 JSON（成功编号 1）。
/// 无单一主密钥（每库独立 key 模式）时 passphrase 置 null，密钥见 keys_saved_to 映射文件。
fn print_json_output(ctx: &JsonOutput) {
    let saved_to = if ctx.has_single_master {
        ctx.output_path.display().to_string()
    } else {
        // 无单一主密钥时 saved_to 指向 keys.json（该文件真实存在）。
        ctx.keys_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default()
    };
    let mut json_data = serde_json::json!({
        "passphrase": ctx.has_single_master.then(|| ctx.passphrase.to_string()),
        "saved_to": saved_to,
        "account": ctx.account_name,
        "databases": ctx.db_count,
    });
    if let Some(ref p) = ctx.keys_path {
        json_data["keys_saved_to"] = serde_json::json!(p.display().to_string());
    }
    println!("{}", messages::json_output(1, json_data));
}

fn main() {
    if let Err(e) = run() {
        if messages::json_mode() {
            let (code, message) = match e.downcast_ref::<messages::WxError>() {
                Some(w) => (w.code, w.message().to_string()),
                None => (-1, format!("{e:#}")),
            };
            eprintln!(
                "{}",
                messages::json_output_with(code, serde_json::Value::Null, &message)
            );
        } else {
            eprintln!("{e:#}");
        }
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let (cmd, args) = parse_args()?;
    // Intel Mac 不支持（README 已验证范围已声明）：命令分派前先报错退出，
    // 而非在 x86_64 上误导性继续执行；restore 等命令同样先报 -24。
    #[cfg(target_os = "macos")]
    ensure!(cfg!(target_arch = "aarch64"), fail(-24));

    match cmd.as_str() {
        "capture" => capture(&args),
        _ => {
            #[cfg(target_os = "macos")]
            {
                platform::restore_and_report(&args.wechat_path)
            }
            #[cfg(not(target_os = "macos"))]
            {
                unreachable!()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_dir_form_rejected_with_minus_26() {
        // `--output /some/dir/` 以分隔符结尾，file_name() 为空，应报 -26 而非写 `.tmp`。
        let err = write_sensitive_json(Path::new("/some/dir/"), "{}").unwrap_err();
        assert_eq!(err.downcast_ref::<messages::WxError>().unwrap().code, -26);
    }

    #[test]
    fn output_existing_dir_rejected_with_minus_26() {
        // `--output` 指向已存在的目录（无尾分隔符）同样应报 -26。
        let dir = std::env::temp_dir().join(format!("wcdb-key-out-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let err = write_sensitive_json(&dir, "{}").unwrap_err();
        assert_eq!(err.downcast_ref::<messages::WxError>().unwrap().code, -26);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
