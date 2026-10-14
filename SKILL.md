---
name: wechat-wcdb-local
description: 微信桌面版 4.x（WCDB/SQLCipher4）本地数据库离线解密与聊天记录提取的 Node.js 跨平台工具（Windows/macOS）。当用户需要从自己设备解密微信 WCDB 加密数据库、提取 Msg_ 表聊天消息、获取微信数据库密钥（Windows 内存 XOR / macOS frida），或生成聊天记录 HTML 报告时使用本技能。
agent_created: true
---

# 微信 WCDB 本地解密与消息提取（Node.js 跨平台）

## 目的

把微信桌面版 4.x 的本地 WCDB/SQLCipher4 加密数据库在**本机离线**解密，并提取聊天记录。提供 Windows 与 macOS 统一的密钥模型与纯 JS 解密后端，无需任何原生编译，两个平台行为一致。

## 何时使用

- 用户想解密自己电脑上的微信数据目录（`db_storage` 下的 `*.db`）。
- 用户想提取某个会话（`Msg_<md5(username)>` 表）的聊天消息。
- 用户需要获取微信数据库密钥：Windows 从进程内存 dump 提取，macOS 用 frida 抓取 `CCKeyDerivationPBKDF` 的 passphrase。
- 用户想把提取结果生成可读的 HTML 报告。

## 打包的工具

本技能在仓库根目录附带一个完整的 Node.js 工具（`package.json` + `bin/wcdb.js` + `src/`）。核心模块：

- `src/constants.js` — XOR 掩码、zstd magic、表名函数、参数常量
- `src/platform.js` — Windows/macOS 数据目录自动定位
- `src/zstd.js` — zstd 解压（`@foxglove/wasm-zstd`，wasm 无原生编译）
- `src/keyExtract.js` — 密钥提取：Win 内存扫描 / dump / 手动
- `src/macKeyFrida.js` — macOS frida 抓 passphrase
- `src/decrypt.js` — passphrase + 每库 salt → enc_key → 解密调度
- `src/wcdbDecode.js` — 纯 JS WCDB/SQLCipher4 页面解码（AES-256-CBC + HMAC-SHA512）
- `src/extract.js` — 消息提取（zstd / local_type / real_sender_id 反推）
- `src/report.js` — HTML 报告生成

详细的加密格式、密钥模型与已知陷阱见 `references/wcdb-crypto.md`。

## 使用流程

### 1. 安装附带工具

在仓库根目录运行：

```bash
npm install
# 可选：macOS frida 抓密钥（仅 Mac 需要）
npm install frida
# 可选：解密回退后端（通常不需要，纯 JS 已覆盖绝大多数场景）
npm install sqlcipher
```

解密是纯 JS 实现，无需任何原生编译；`better-sqlite3` 自带预编译二进制，一般装完即用。

### 2. 获取密钥（passphrase）

- 已知密钥：直接用 `--key <hex>`。
- Windows 内存 dump（最稳妥，跨平台）：`node bin/wcdb.js key --dump wcdb_blob.bin -o keys.json`
- Windows 实时扫描（实验性，需 `--allow-memory-scan`）：`node bin/wcdb.js key --allow-memory-scan -o keys.json`
- macOS frida（需重签名微信 + root）：`sudo node bin/wcdb.js key --mac-frida -o keys.json`

### 3. 解密数据库

```bash
node bin/wcdb.js decrypt --dir <db_storage路径> --keys keys.json --out plain/
# 或已知 passphrase 时
node bin/wcdb.js decrypt --dir <db_storage路径> --key <passphrase_hex> --out plain/
```

解密默认走纯 JS 后端；若个别微信版本异常，加 `--backend sqlcipher` 回退到原生模块。

### 4. 提取消息

```bash
node bin/wcdb.js extract --db plain/message_0.plain.db --username wxid_xxxx --self-wxid wxid_you --out messages.json
```

### 5. 生成报告

```bash
node bin/wcdb.js report --in messages.json --out report.html
```

### 6. 自测

```bash
npm test
```

## 跨平台兼容性

本技能**同时支持 Windows 与 macOS**，关键保证如下：

- **平台探测**：`detectPlatform()` 用 `process.platform` 区分 `win32` / `darwin` / 其他，数据目录定位各自独立实现（`resolveWindowsDataDir` 读 `%APPDATA%`+`.ini`，`resolveMacDataDir` 扫 `~/Library/Containers/com.tencent.xinWeChat/...`）。
- **平台代码隔离**：Windows 实时内存扫描（`Kernel32.dll` + koffi）与 macOS frida 抓取互相隔离，未命中对应平台时给出明确指引而非崩溃；`koffi` / `frida` 均为**惰性 `require`**，不会在另一平台加载期报错。
- **路径跨平台**：临时文件统一用 `os.tmpdir()` + `path.join` 构造（如 passphrase 落盘 `wxdb/passphrase.hex`），不写死 `/tmp`，Windows 上自动落到 `AppData\Local\Temp`。
- **依赖双平台可用**：`@foxglove/wasm-zstd`（wasm 无原生）、`better-sqlite3`（有 win/mac 预编译）、`commander`（纯 JS）、`koffi`（有 win/mac 预编译）均可在两系统 `npm install`；`sqlcipher` 仅为 `optionalDependencies` 回退；`frida` 仅 macOS 按需 `npm install frida`。
- **CLI 跨平台**：`bin/wcdb.js` 用 `#!/usr/bin/env node`，Windows 下 npm 自动生成 `.cmd` 包装，`wcdb` 命令可用。

## 关键注意事项

- **法律与隐私**：仅用于读取本人设备数据，遵守当地法律法规与微信用户协议；全程本机处理，数据不上传。
- **macOS 无 `Config.Cipher`**：Mac 版微信只有 frida 路径，详见 `references/wcdb-crypto.md`。
- **未真机验证项**：纯 JS 对真实微信 4.x `.db` 解密、Windows 实时内存扫描、macOS frida 抓取均依赖真实环境，需在真机确认。
- **local_type 取低 32 位**；群消息发送者由 `wxid_xxx:\n` 前缀反推；`real_sender_id` 每个 `message_N.db` 独立，库内无映射表。
- **重签名保留 sandbox**：删掉 `com.apple.security.app-sandbox` 会让微信切到另一数据目录，读不到已有记录。
