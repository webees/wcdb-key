# wcdb-key

> 提取 WX 4.x 的 WCDB 主密钥（passphrase）。纯本地，零网络，结束自动还原 WX 原样。

候选密钥须通过账号下全部加密数据库的 page-1 HMAC（PBKDF2-SHA512 × 256000 轮），任一失败整体拒绝。
仅用于自己的设备、自己的账号，见[免责声明](#免责声明)。

## 使用

命名、注释、消息编号、测试等编程规范见 [CODING.md](CODING.md)。

```bash
cargo build --release          # Rust 1.82+；macOS 需 Xcode CLT（lldb）
./target/release/wcdb-key capture [--db-dir <PATH>] [--timeout <SECONDS>] [--output <PATH>] [--json]
./target/release/wcdb-key capture --wechat-path <PATH>   # 仅 macOS
./target/release/wcdb-key restore                        # 仅 macOS：从备份恢复官方版本
```

| 选项 | 默认 | 说明 |
|:------------------|:--------|:-----------------------------|
| `--db-dir` | 自动发现 | 账号数据目录（含 `db_storage`），多账号交互选择 |
| `--timeout` | 900 | 捕获超时秒数（Windows 为扫描预算） |
| `--output` | `~/.wcdb-key/wechat-passphrase.json` | 密钥保存文件路径，0600 |
| `--wechat-path` | `/Applications/WeChat.app` | 微信安装路径，仅 macOS |
| `--json` | off | stdout 只出结果 JSON，日志与提示走 stderr，错误 JSON 化退出码 1 |
| `--version`, `-V` | — | 打印版本号并退出 |
| `-h`, `--help`, `help` | — | 显示帮助 |

```console
$ wcdb-key capture --json 2>/dev/null
{"code":1,"data":{"passphrase":"…","saved_to":"…","account":"…","databases":31},"msg":"操作完成"}

$ wcdb-key capture --json --timeout abc 2>&1 >/dev/null
{"code":-13,"data":null,"msg":"--timeout 需要整数秒"}
```

> **`--json` 输出中 `passphrase` 字段语义**：仅当存在单一主密钥时输出 64 位 hex（macOS 恒有；Windows 主密钥探测通过——所有库同 key——时也有）。
> Windows 4.1.12+ 每库独立 key 模式下无单一主密钥，`passphrase` 为 `null`，实际密钥保存在 `*.keys.json` 映射文件，`keys_saved_to` 字段给出其路径。
> **`--json` 与多账号交互**：stdout 始终只输出结果 JSON；多账号时账号列表与选择提示经 stderr 输出、选择序号仍从 stdin 读取，因此无账号命中时 stdout 保持为空。

## 原理

WX 4.1 起，passphrase（32 字节随机值）只在登录瞬间经 `CCKeyDerivationPBKDF`
做 PBKDF2-SHA512 × 256000 轮派生，随后从内存消失——事后扫描无效，
必须在派生瞬间从寄存器读走原料，断点挂在这里。

**macOS**（sandbox + hardened runtime，无法直接附加）：
APFS 克隆备份 → ad-hoc 重签去 sandbox → 直接 exec 主二进制（不经 LaunchServices）→
LLDB 附加 → 登录捕获 → 原子恢复官方签名

```text
quit → clonefile 备份 → codesign -s - (去 sandbox) → exec binary
  → lldb attach → software bp: CCKeyDerivationPBKDF
  → login → x1=passphrase(32B) x3=salt(16B) x6=256000
  → HMAC(page1) 通过 → SIGKILL 临时进程 → restore official + 深度验签
```

**Windows**（进程内存无保护，无需重启）：
Toolhelp32 枚举进程 → 定位 `com.Tencent.WCDB.Config.Cipher` 对象链 →
解引用读取每库密钥 blob（XOR 解码 + `x'<hex>'` 字面量提取）→ 逐库 HMAC 匹配

```text
Toolhelp32 枚举 Weixin.exe → OpenProcess(VM_READ)
  → 全内存 memchr "com.Tencent.WCDB.Config.Cipher"
  → 构造 (地址,长度) 对模式找引用 → node+0x28 → config+0x88 → Data blob
  → XOR 解码 → x'<96hex>' 提取 32B key → 每库 HMAC 校验
```

> **Windows 4.1.12+ 登录后无单一主密钥**：登录后原始 passphrase 即擦除，内存中仅为每个数据库保留独立的已派生密钥（Config.Cipher blob）。工具自动提取全部每库密钥并保存映射文件 `*.keys.json`；macOS 4.1.13 仍存在单一主密钥（登录瞬间 LLDB 捕获）。若某版本恢复单 passphrase 也会自动识别。

解密：passphrase 兼容 WCDB/SQLCipher 工具（raw key 与派生 key 均校验），
AES-256-CBC 逐页解密还原标准 SQLite。Windows 每库密钥即该库的 raw key，
可直接用于 `PRAGMA key = "x'<hex>'"`。

## FAQ

| 问题 | 回答 |
|---|---|
| 封号风险？ | 与腾讯服务器零交互；捕获发生在本地登录流程内，读一次寄存器即结束。多版本实测无异常 |
| 为什么不需要 sudo？ | ad-hoc 重签去掉 sandbox，直接 exec 启动绕开 LaunchServices，普通用户的 LLDB 即可附加；不重签、硬附加官方版本的工具才需要 sudo |
| WX 升级后？ | macOS 断点挂系统 CommonCrypto 符号，与版本解耦（跨版本实测零改动）；Windows 对象链偏移与 XOR 掩码依赖版本，4.1.13.12 已实测，更新后若失败需重新提取掩码 |
| passphrase 会轮换吗？ | 多版本捕获结果同值，退出重登不轮换；换设备或重装可能轮换 |

## 项目结构

```text
src/
├── main.rs      CLI 解析、流程编排、--json 输出
├── shared.rs    跨平台：账号发现、加密库扫描、并行全库校验
├── crypto.rs    PBKDF2 派生 + page-1 HMAC 校验核心
├── mac.rs       macOS：签名校验/事务重签/LLDB 监测
├── hook.py      LLDB 回调脚本（编译期嵌入）
├── win.rs       Windows：进程枚举 + 内存特征扫描
└── messages.rs  编号消息系统（注册表 messages.json）
```

## 故障排查

| 现象 | 处理 |
|---|---|
| `[-209] LLDB 无法附加` | 确认 WX 为官方 Developer ID 签名（工具会先临时重签）；重试 |
| `[-213] 等待登录超时` | 自动登录的派生可能发生在附加前——退出账号重新登录 |
| `[-219] 未找到可用数据库 salt` | 账号数据目录无加密数据库，确认 `--db-dir` 指向正确的账号目录 |
| `[-302] Windows 未找到候选` | 确认 WX 已登录且数据目录与登录账号一致 |
| 恢复失败 `[-216]` | 备份保留在 `~/.wcdb-key/backup/`，执行 `wcdb-key restore` |
| 其他 | 附上完整编号输出提 issue；失败时 LLDB 日志保留在系统临时目录 `wcdb-key-<pid>/`（提示编号 211） |

## 消息编号

所有输出带编号，注册表为编译期嵌入的 `src/messages.json`，禁止内联文本（i18n 改 JSON 即可）。

| 规则 | 说明 |
|---|---|
| 调用方式 | 只传数字：`say(105)`、`fail(-201)` |
| 符号语义 | `> 0` 信息；`< 0` 错误（进程退出码 1） |
| 未知编号 | 回退 `-505` |

| 编号区间 | 内容 |
|---|---|
| `1–99` / `-1–-99` | 通用与 CLI |
| `100–199` / `-100–-199` | 主流程 |
| `200–299` / `-200–-299` | macOS |
| `300–399` / `-300–-399` | Windows |
| `-500–-599` | 底层命令/IO |

## 测试

```bash
cargo test                    # 16 例通过（密码学往返/拒绝 6 例）
cargo clippy --release        # 0 警告
cargo check --target x86_64-pc-windows-msvc
WCDB_TEST_DB_DIR=<db_storage> WCDB_TEST_PASSPHRASE=<hex> cargo test -- --ignored
```

## 安全设计

| 设计点 | 说明 |
|---|---|
| 事务性恢复（macOS） | 成功/失败/Ctrl-C 任一路径自动恢复官方版本并深度验签（厂商 Team ID `5A4RE8SF68`）；恢复为"暂存克隆 + 原子交换"，不会让系统处于无可用状态 |
| 全库校验 | 候选须通过全部加密数据库，按核数并行，线程异常视为整体失败 |
| 零网络 / 最小痕迹 | 无任何网络请求；密钥仅结束打印一次并落盘 0600；临时目录 0700 用后即焚；SIGKILL 临时进程避免崩溃上报 |

## 已验证范围

| 平台 | 系统版本 | 微信版本 | 状态 | 说明 |
|---|---|---|---|---|
| macOS (Apple Silicon) | macOS 27 Sequoia, M5 Pro | 4.1.13 (build 269579) | ✅ | 完整端到端：LLDB 断点 CCKeyDerivationPBKDF 登录瞬间捕获单一 passphrase，全体数据库 HMAC 校验通过 |
| Windows (ARM64 模拟 x64) | Windows 11 IoT Enterprise LTSC, build 26100, Parallels VM | 4.1.13.12 | ✅ | 对象链扫描提取每库独立密钥（21 个唯一 key 匹配 19/19 库 HMAC），输出 `*.keys.json` 映射。**Windows 4.1.12+ 登录后无单一主密钥（macOS 4.1.13 仍保留）** |
| Intel Mac、WX 未来版本 | — | — | ❌ | 不支持 |

## 免责声明

仅限处理使用者本人合法持有的数据。使用过程修改 WX 签名状态，可能违反其许可协议并存在账号风险，后果自负。不对准确性、稳定性或持续可用性作任何保证。

## 致谢

- [TANGandXUE/wcdb-key-tool](https://github.com/TANGandXUE/wcdb-key-tool) — 三平台方案对照与兼容性参照
- [LifeArchiveProject/WeChatDataAnalysis](https://github.com/LifeArchiveProject/WeChatDataAnalysis) — 事务性重签/恢复流程与验证核心参考
- [Tencent/wcdb](https://github.com/Tencent/wcdb) — 数据库框架本体

## License

[MIT](LICENSE) © 2026 webees
