//! 数字编号消息注册表——编译期嵌入的 JSON（`src/messages.json`）。
//! 每条用户可见的消息都有数字编号：`> 0` 为成功/信息，
//! `< 0` 为错误。调用处只传编号：`say(205)`、`fail(-201)`。
//! JSON 文件是唯一事实来源；禁止在代码中内联文本。

use anyhow::Error;
use std::collections::HashMap;
use std::fmt::Display;
use std::sync::OnceLock;

const REGISTRY_JSON: &str = include_str!("messages.json");

fn registry() -> &'static HashMap<i32, String> {
    static REGISTRY: OnceLock<HashMap<i32, String>> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        // ponytail: 这两个 expect 是元错误——注册表自身损坏时，
        // 无法再用注册表翻译自己的 panic 文本，故保留字面量。
        serde_json::from_str::<HashMap<String, String>>(REGISTRY_JSON)
            .expect("messages.json 不是合法的消息注册表")
            .into_iter()
            .map(|(k, v)| (k.parse::<i32>().expect("消息编号必须是整数"), v))
            .collect()
    })
}

/// 查询 `code` 对应文本。未知编号回退到 -505
/// （编号本身仍会随输出打印，便于排查）。
pub(crate) fn msg(code: i32) -> &'static str {
    registry()
        .get(&code)
        .or_else(|| registry().get(&-505))
        .map(String::as_str)
        .unwrap_or("-505")
}

fn render(template: &str, args: &[&str]) -> String {
    args.iter()
        .enumerate()
        .fold(template.to_string(), |acc, (i, arg)| {
            acc.replace(&format!("{{{i}}}"), arg)
        })
}

/// 带编号的错误；`Display` 输出 `[-编号] 文本`。
#[derive(Debug)]
pub struct WxError {
    /// 错误编号（正数：信息，负数：错误）。
    pub code: i32,
    rendered: String,
}

impl Display for WxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{0}] {1}", self.code, self.rendered)
    }
}

impl std::error::Error for WxError {}

impl WxError {
    /// 返回错误消息文本（不含编号）。
    pub fn message(&self) -> &str {
        &self.rendered
    }
}

// --json 模式下 stdout 只输出最终结果 JSON；
// 所有人类可读消息（含交互提示）一律改走 stderr。
static JSON_MODE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// 设置 JSON 输出模式。
pub fn set_json_mode(on: bool) {
    JSON_MODE.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// 当前是否为 JSON 输出模式。
pub fn json_mode() -> bool {
    JSON_MODE.load(std::sync::atomic::Ordering::Relaxed)
}

/// 创建编号错误（无参数）。
pub fn fail(code: i32) -> Error {
    WxError {
        code,
        rendered: msg(code).to_string(),
    }
    .into()
}

/// 创建编号错误（带参数）。
pub fn failf(code: i32, args: &[&str]) -> Error {
    WxError {
        code,
        rendered: render(msg(code), args),
    }
    .into()
}

fn emit(code: i32, args: &[&str], stderr: bool) {
    let text = render(msg(code), args);
    if stderr {
        eprintln!("[{code}] {text}");
    } else {
        println!("[{code}] {text}");
    }
}

/// 输出编号消息（无参数）。
pub fn say(code: i32) {
    emit(code, &[], json_mode());
}

/// 输出编号消息（带参数）。
pub fn sayf(code: i32, args: &[&str]) {
    emit(code, args, json_mode());
}

/// 构造 --json 模式的三字段结果 JSON（msg 取 code 对应文案）。
pub fn json_output(code: i32, data: serde_json::Value) -> String {
    json_output_with(code, data, msg(code))
}

/// json_output 的变体：msg 使用已渲染文本（错误消息已含占位符替换）。
pub fn json_output_with(code: i32, data: serde_json::Value, message: &str) -> String {
    serde_json::json!({ "code": code, "data": data, "msg": message }).to_string()
}

/// 警告级消息输出到 stderr（恢复通知、跳过项等）。
pub fn warn(code: i32, args: &[&str]) {
    emit(code, args, true);
}

/// 交互选择用的提示符（不换行）。
pub fn ask(code: i32) {
    let text = format!("[{code}] {}", msg(code));
    if json_mode() {
        eprint!("{text}");
        let _ = std::io::Write::flush(&mut std::io::stderr());
    } else {
        print!("{text}");
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }
}

/// 为非预期错误（IO 等）附加编号，同时保留原始错误文本。
pub fn fail_io(code: i32, source: impl Display) -> Error {
    failf(code, &[&source.to_string()])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_loads_and_codes_are_valid_ints() {
        // 注册表解析失败会在首次调用时 panic——这里显式触发以尽早暴露。
        assert!(!registry().is_empty());
        for code in registry().keys() {
            assert!(*code != 0, "编号 0 未定义语义");
        }
    }

    #[test]
    fn unknown_code_falls_back_to_minus_505() {
        assert_eq!(msg(-99999), msg(-505));
    }

    #[test]
    fn render_substitutes_positional_args() {
        assert_eq!(render("a {0} b {1} c {0}", &["X", "Y"]), "a X b Y c X");
        // 未提供的占位符保持原样。
        assert_eq!(render("{0} {2}", &["X"]), "X {2}");
    }

    #[test]
    fn wxerr_display_carries_code() {
        assert_eq!(fail(-201).to_string(), format!("[-201] {}", msg(-201)));
        assert_eq!(
            failf(-105, &["2", "x.db"]).to_string(),
            format!("[-105] {}", render(msg(-105), &["2", "x.db"]))
        );
    }
}
