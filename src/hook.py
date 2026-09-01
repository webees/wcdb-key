"""LLDB 内嵌回调脚本（编译期由 mac.rs include_str! 嵌入）。

在系统公开符号 `CCKeyDerivationPBKDF` 上放置软件断点：
按微信的参数形状（algorithm=2、len=32/16、prf=5、rounds=256000）
与账号数据库 salt 过滤调用，候选通过探测库 page-1 HMAC
校验后写回结果，并终止一次性临时微信进程。

本脚本的 page-1 HMAC 校验逻辑（`_matches`）与 `src/crypto.rs` 的
`page1_hmac_of` 保持一致（LLDB 回调脚本仅支持 Python，无法复用
Rust 实现；两处需同步修改）。

运行时替换占位符：@RESULT_PATH@、@SALTS@、@PAGE1@。
"""

import hashlib
import hmac
import json
import os
import lldb

RESULT_PATH = "@RESULT_PATH@"
EXPECTED_SALTS = frozenset(@SALTS@)
PROBE_PAGE1 = bytes.fromhex("@PAGE1@")
KEY_ROUNDS = 256000

DIAG = {"pbkdf_calls": 0, "shape_hits": 0, "salt_hits": 0, "rejected": 0}


def _write(payload):
    fd = os.open(RESULT_PATH, os.O_WRONLY | os.O_TRUNC | os.O_CREAT, 0o600)
    try:
        data = json.dumps(payload).encode()
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def _reg(frame, name):
    return frame.FindRegister(name).GetValueAsUnsigned()


def _matches(candidate):
    salt = PROBE_PAGE1[:16]
    stored = PROBE_PAGE1[4032:4096]
    for enc_key in (candidate, hashlib.pbkdf2_hmac("sha512", candidate, salt, KEY_ROUNDS, 32)):
        mac_salt = bytes(b ^ 0x3A for b in salt)
        mac_key = hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, 32)
        d = hmac.new(mac_key, digestmod=hashlib.sha512)
        d.update(PROBE_PAGE1[16:4032])
        d.update((1).to_bytes(4, "little"))
        if hmac.compare_digest(stored, d.digest()):
            return True
    return False


def _save(process, candidate):
    if not _matches(candidate):
        DIAG["rejected"] += 1
        _write({"diagnostics": dict(DIAG)})
        return False
    _write({"passphrase": candidate.hex(), "source": "pbkdf2_passphrase", "diagnostics": dict(DIAG)})
    print("WCDB_KEY_CAPTURED", flush=True)
    process.Kill()
    os._exit(0)


def _pbkdf_callback(frame, bp_loc, _internal_dict):
    process = frame.GetThread().GetProcess()
    DIAG["pbkdf_calls"] += 1
    if (
        _reg(frame, "x0") != 2
        or _reg(frame, "x2") != 32
        or _reg(frame, "x4") != 16
        or _reg(frame, "x5") != 5
        or _reg(frame, "x6") != KEY_ROUNDS
    ):
        return False
    DIAG["shape_hits"] += 1
    err = lldb.SBError()
    salt = process.ReadMemory(_reg(frame, "x3"), 16, err)
    if not err.Success() or len(salt) != 16:
        return False
    if salt.hex() not in EXPECTED_SALTS:
        return False
    DIAG["salt_hits"] += 1
    password = process.ReadMemory(_reg(frame, "x1"), 32, err)
    if not err.Success() or len(password) != 32:
        return False
    _save(process, password)
    return False


def __lldb_init_module(debugger, _internal_dict):
    target = debugger.GetSelectedTarget()
    bp = target.BreakpointCreateByName("CCKeyDerivationPBKDF")
    bp.SetScriptCallbackFunction(__name__ + "._pbkdf_callback")
    bp.SetAutoContinue(True)
    locations = bp.GetNumResolvedLocations()
    print("WCDB_KEY_MONITOR_READY", locations, flush=True)
    if locations <= 0:
        _write({"error": "no_breakpoint_locations"})
        target.GetProcess().Detach()
        os._exit(24)
